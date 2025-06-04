## Search VirusTotal for a file hash
## VirusTotal Public API: https://developers.virustotal.com/reference#file-report

## Get your own VT API key here: https://www.virustotal.com/gui/join-us
    $VTApiKey = "5e8675e45afaf31d895d9a5f66692999ccaec67b3361e21b33c83d58c129814c"
    $HashListFile = ".\MD5_list_only.txt"      # Input File with hash line by line
    $ResultFile= ".\Result_VT.csv"        # Output File in CSV File format

## Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
    $sleepTime = 16

## Set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## Purge result file
If ((Test-Path  $ResultFile))
{   
    Remove-Item $ResultFile
    $samples=""
}

Function submit-VTHash($VThash)
{
    $VTbody = @{resource = $VThash; apikey = $VTApiKey}
    $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody

    return $vtResult
}

$text = ("Resource;Scan_date;Positives;Total;Permalink;Percent") -join "";
$string = Write-Output $text >> $ResultFile

foreach ($hash in Get-Content $HashListFile)
{
    ## Submit the hash!
        $VTresult = submit-VTHash($hash)
            
    ## Color positive results
        if ($VTresult.positives -ge 1) {
            $fore = "Magenta"
            $VTpct = (($VTresult.positives) / ($VTresult.total)) * 100
            $VTpct = [math]::Round($VTpct,2)
        }
        else {
            $fore = (get-host).ui.rawui.ForegroundColor
            $VTpct = 0
        }

    ## Display results
        Write-Host "==================="
        Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTresult.resource
        Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTresult.scan_date
        Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTresult.positives
        Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTresult.total
        Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTresult.permalink
        Write-Host -f Cyan "Percent     : " -NoNewline; Write-Host $VTpct "%"
        
     ## building result VT file

        $text = ($hash,";",$VTresult.scan_date,";",$VTresult.positives,";",$VTresult.total,";",$VTresult.permalink,";",$VTpct,"%") -join ""; 
        $string = Write-Output $text >> $ResultFile

        Start-Sleep -seconds $sleepTime

}



