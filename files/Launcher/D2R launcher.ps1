#== D2R multiclient transparent launcher by Chobot - https://github.com/Chobotz/D2R-multiclient-tools =====
#== Update to D2R fast launcher by faliny - https://github.com/faliny/D2R-fast-launcher =====

param($operation, $param1, $param2)

Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    public static class Win32 {
        [DllImport("User32.dll", EntryPoint="SetWindowText")]
        public static extern int SetWindowText(IntPtr hWnd, string strTitle);
    }
"@

Add-Type -Namespace Util -Name WinApi -MemberDefinition @"
    [DllImport("user32.dll")]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
"@

Add-Type -Namespace System.Text -Name WinApi -MemberDefinition @"
    [DllImport("Kernel32")]
    public static extern long WritePrivateProfileString(string section, string key, string val,string filePath);
    [DllImport("Kernel32")]
    public static extern int GetPrivateProfileString(string section, string key, string def, StringBuilder retVal, int size, string filePath);
    [DllImport("Kernel32")]
    public static extern long WritePrivateProfileSection(string section, StringBuilder val, string filePath);
    [DllImport("Kernel32")]
    public static extern int GetPrivateProfileSectionNames(Byte[] retVal, int size, string filePath);
"@

clear

$script:d2rRoot = $PSScriptRoot.Substring(0, $PSScriptRoot.LastIndexOf('\'))
$script:userInfoFilePath = $PSScriptRoot + "\user_info.ini"
$script:defaultRegion = "kr"
$script:userList = New-Object System.Collections.ArrayList
$script:userInfoMap = [ordered]@{ }
$script:regionList = @("kr", "eu", "us")
$script:regionDescMap = [ordered]@{
    "kr" = "�Ƿ�"
    "eu" = "ŷ��"
    "us" = "����"
}
$script:buff = New-Object System.Text.StringBuilder(1024)

function getConfig($module, $key)
{
    $null = [System.Text.WinApi]::GetPrivateProfileString($module, $key, "", $script:buff, $script:buff.Capacity, $script:userInfoFilePath)
    return $script:buff.tostring()
}

function saveConfig($module, $key, $value)
{
    $null = [System.Text.WinApi]::WritePrivateProfileString($module, $key, $value, $script:userInfoFilePath)
}

function deleteModule($module)
{
    $null = [System.Text.WinApi]::WritePrivateProfileSection($module, $null, $script:userInfoFilePath)
}

function init
{
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
    {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $operation $param1 $param2" -Verb RunAs; exit
    }

    if (![System.IO.File]::Exists("$script:d2rRoot\D2R.exe"))
    {
        Write-Host "`n����:�뽫��ݵ�¼���ļ��з�����D2R��Ŀ¼��"
        Read-host "����س��˳�..."
        Exit
    }

    if (![System.IO.File]::Exists("$PSScriptRoot\handle64.exe"))
    {
        Write-Host "`n����:������handle64.exe��������D2R��Ŀ¼��Launcher�ļ����£��ͽű���ͬһ���ļ��С����ص�ַ: https://docs.microsoft.com/en-us/sysinternals/downloads/handle"
        Read-host "����س��˳�..."
        Exit
    }

    if (![System.IO.File]::Exists($script:userInfoFilePath))
    {
        $null = New-Item -ItemType File $script:userInfoFilePath
    }

    $script:userInfoMap.Clear()
    $script:userList.Clear()

    $buffer = New-Object Byte[] 2048
    $num = [System.Text.WinApi]::GetPrivateProfileSectionNames($buffer, 2048, $script:userInfoFilePath)
    $users = @()
    $start = 0
    $conut = 0
    $num = $num - 1

    foreach ($i in 0..$num)
    {
        if ($buffer[$i] -eq '0')
        {
            $conut = $i - $start
            if ($conut -gt 0)
            {
                $str = [System.Text.Encoding]::ASCII.GetString($buffer, $start, $conut)
                $users += $str
            }
            $start = $i + 1
        }
    }

    if (![string]::IsNullOrWhiteSpace($users))
    {
        foreach ($user in $users)
        {
            $password = getConfig $user "password"
            if ( [string]::IsNullOrWhiteSpace($password))
            {
                continue
            }
            $userInfo = @{ "password" = $password }

            $region = getConfig $user "region"
            if ( [string]::IsNullOrWhiteSpace($region))
            {
                $region = "$defaultRegion"
            }
            $userInfo.add("region", $region)

            $mod = getConfig $user "mod"
            if (![string]::IsNullOrWhiteSpace($mod))
            {
                $userInfo.add("mod", $mod)
            }

            $fullScreen = getConfig $user "fullScreen"
            if (![string]::IsNullOrWhiteSpace($fullScreen))
            {
                $userInfo.add("fullScreen", $fullScreen)
            }

            $script:userInfoMap.add($user, $userInfo)
        }
        foreach ($key in $script:userInfoMap.keys)
        {
            $null = $script:userList.Add($key)
        }
    }
}

function showUsersInfo
{
    Write-Host "`n�����˺���Ϣ���£�`n"
    $num = 1
    $script:userInfoMap.GetEnumerator() | ForEach-Object {
        $fullScreen = $_.value["fullScreen"]
        if ([string]::IsNullOrWhiteSpace($fullScreen) -or $fullScreen -ne "1")
        {
            $fullScreen = "��"
        }
        else
        {
            $fullScreen = "��"
        }

        $message = "    [{0}] �û�����{1,-25} ������{2,-4} Mod���ƣ�{3,-15} �Ƿ�ȫ����{4,-2}" -f $num++, $_.key, $script:regionDescMap[$_.value["region"]], $_.value["mod"], $fullScreen
        Write-Host $message
    }
    Write-Host "`n"
}

function showRegions
{
    Write-Host "`n������Ϣ���£�"
    $num = 1
    $script:regionDescMap.GetEnumerator() | ForEach-Object {
        $message = '    [{0}] {1}' -f $num++, $_.value
        Write-Output $message
    }
}

function closeHandle
{
    & "$PSScriptRoot\handle64.exe" -accepteula -a -p D2R.exe > $PSScriptRoot\d2r_handles.txt

    $proc_id_populated = ""
    $handle_id_populated = ""

    foreach ($line in Get-Content $PSScriptRoot\d2r_handles.txt)
    {
        $proc_id = $line | Select-String -Pattern '^D2R.exe pid\: (?<g1>.+) ' | %{ $_.Matches.Groups[1].value }
        if ($proc_id)
        {
            $proc_id_populated = $proc_id
        }
        $handle_id = $line | Select-String -Pattern '^(?<g2>.+): Event.*DiabloII Check For Other Instances' | %{ $_.Matches.Groups[1].value }
        if ($handle_id)
        {
            $handle_id_populated = $handle_id
        }

        if ($handle_id)
        {
            Write-Host "Closing" $proc_id_populated $handle_id_populated
            & "$PSScriptRoot\handle64.exe" -p $proc_id_populated -c $handle_id_populated -y
        }
    }
}

function setWindowName($ctitle)
{
    Start-Sleep -Seconds 2
    $waittime = 1
    while ($waittime -lt 10)
    {
        $d2handle = [Util.WinApi]::FindWindow([NullString]::Value, "Diablo II: Resurrected")
        if ($d2handle -ne 0)
        {
            [Win32]::SetWindowText($d2handle, $ctitle)
            Break
        }
        Start-Sleep -Seconds 1
        $waittime = $waittime + 1
    }
}

function validUserName($userNames)
{
    try
    {
        foreach ($userName in $userNames)
        {
            if (!$script:userInfoMap.Contains($userName.Trim()))
            {
                return $false
            }
        }
        return $true
    }
    catch
    {
        return $false
    }
}

function indexesAllValid($list, $indexs)
{
    try
    {
        $indexs = $indexs.split(' ')
        foreach ($index in $indexs)
        {
            $index = $index.Trim()/1
            if ($index -le 0 -or $index -gt $list.Count)
            {
                return $false
            }
        }
        return $true
    }
    catch
    {
        return $false
    }
}

function validUserInfo($userInfo)
{
    try
    {
        if ($userInfo.Count -lt 3)
        {
            return $false
        }

        if ([string]::IsNullOrWhiteSpace($userInfo[0]) -or [string]::IsNullOrWhiteSpace($userInfo[1]) -or [string]::IsNullOrWhiteSpace($userInfo[2]))
        {
            return $false
        }

        if (!$script:regionDescMap.Contains($userInfo[2]))
        {
            return $false
        }

        return $true
    }
    catch
    {
        return $false
    }
}

function startFromConfig($userNames)
{
    foreach ($userName in $userNames)
    {
        $userName = $userName.trim()
        Write-Host "`n������Ϸ����ǰ�˺ţ�$userName"
        Write-Host "���������п�����ʱͨ��ͬʱ���� Ctrl + C ��ֹ����"

        closeHandle

        $password = $script:userInfoMap[$userName]["password"] | ConvertTo-SecureString
        $cred = New-Object -TypeName System.Management.Automation.PSCredential("JustGiveAName", $password)
        $password = $cred.GetNetworkCredential().Password
        $region = $script:userInfoMap[$userName]["region"]
        $mod = $script:userInfoMap[$userName]["mod"]
        $fullScreen = $script:userInfoMap[$userName]["fullScreen"]

        if ([string]::IsNullOrWhiteSpace($fullScreen) -or $fullScreen -ne "1")
        {
            $fullScreen = "-w"
        }
        else
        {
            $fullScreen = ""
        }

        $p = "-username $userName -password $password -address $region.actual.battle.net $fullScreen -mod $mod"
        [Array]$p = $p.Split(' ')

        & $script:d2rRoot\D2R.exe $p

        Start-Sleep -Seconds 2
        setWindowName $userName
    }
}

function checkExist($userName)
{
    if ( $script:userInfoMap.Contains($userName.Trim()))
    {
        Write-Host "`n���˺��Ѵ���"
        return $true
    }
    return $false
}

function main($op, $p1, $p2)
{
    clear
    init
    if ( [string]::IsNullOrWhiteSpace($op))
    {
        $mainOps = [ordered]@{
            "1" = @("startAll", "���������˺�")
            "2" = @("startBatch", "��������ָ���˺�")
            "3" = @("showAllUser", "չʾ�����˺�")
            "4" = @("add", "����˺�")
            "5" = @("update", "�޸��˺�")
            "6" = @("delete", "ɾ���˺�")
            "7" = @("createStartRef", "���������˺�������ݷ�ʽ������")
            "8" = @("createAllStartRef", "����һ������ȫ���˺ſ�ݷ�ʽ������")
            "9" = @("createUpdateAllRegionRef", "����һ���޸�ȫ���˺ŷ�����ݷ�ʽ������")
            "0" = @("help", "����")
        }

        Write-Host "`n��ѡ��һ�������������Ӧ����ţ�`n"
        $mainOps.GetEnumerator() | ForEach-Object {
            $message = "    [{0}] {1}" -f $_.key, $_.value[1]
            Write-Host "$message"
        }
        Write-Host "`n"

        Do
        {
            $opIndex = Read-Host '�����������Ӧ�����'
        }
        while ( !$mainOps.Contains($opIndex))
        $op = $mainOps[$opIndex][0]
    }

    try
    {
        & $op $p1 $p2
    }
    catch
    {
        Write-Host "`n����:��������ȷ�Ĳ�������"
        Read-host "����س��˳�..."
        Exit
    }
}

function add()
{
    Write-Host "`n"
    Do
    {
        $userName = Read-Host '������׼����ӵ��˺�'
    }
    while ( [string]::IsNullOrWhiteSpace($userName) -or (checkExist $userName) )

    Do
    {
        $password = Read-Host '�������˺Ŷ�Ӧ������' -AsSecureString
    }
    while ( [string]::IsNullOrWhiteSpace($password))

    $password = $password | ConvertFrom-SecureString

    showRegions

    Do
    {
        $regionIndex = Read-Host '��ѡ������������Ӧ�����'
    }
    while ( !(indexesAllValid $script:regionList $regionIndex))

    Write-Host "`n"
    $mod = Read-Host '������mod���ƣ�����ȡս��������-mod֮���������Ϣ����ʹ��mod��ֱ�Ӱ��س�'

    $fullScreenConfigs = @("1", "")
    Do
    {
        Write-Host "`n"
        $fullScreen = Read-Host '�Ƿ�ȫ��������Ϸ��ѡ������:
    [1] ��
    [2] ��
��ѡ��ѡ������Ӧ�����'
    }
    while ( !(indexesAllValid $fullScreenConfigs $fullScreen))

    $userInfo = @{
        "password" = $password
        "region" = $script:regionList[$regionIndex - 1]
        "mod" = $mod
        "fullScreen" = $fullScreenConfigs[$fullScreen - 1]
    }

    $userName = $userName.trim()
    saveConfig $userName "password" $userInfo["password"]
    saveConfig $userName "region" $userInfo["region"]
    saveConfig $userName "mod" $userInfo["mod"]
    saveConfig $userName "fullScreen" $userInfo["fullScreen"]

    Write-Host "`n���/�޸ĳɹ�"
    Read-host "����س�����..."
    main
}

function updatePwd($userNames)
{
    Do
    {
        $password = Read-Host '�������µ�����' -AsSecureString
    }
    while ( [string]::IsNullOrWhiteSpace($password))

    $password = $password | ConvertFrom-SecureString

    foreach ($userName in $userNames)
    {
        saveConfig $userName "password" $password
    }

    Write-Host "`n�޸����"
    Read-host "����س�����..."
}

function updateRegion($userNames)
{
    if ($userNames -eq "`$0")
    {
        $userNames = $script:userList
    }

    showRegions
    Do
    {
        $regionIndex = Read-Host '��ѡ������������Ӧ�����'
    }
    while ( !(indexesAllValid $script:regionList $regionIndex))

    foreach ($userName in $userNames)
    {
        saveConfig $userName "region" $script:regionList[$regionIndex - 1]
    }

    Write-Host "`n�޸����"
    Read-host "����س�����..."
}

function updateMod($userNames)
{
    $mod = Read-Host '������mod���ƣ�����ȡս��������-mod֮���������Ϣ����ɾ��modֱ�Ӱ��س�'

    foreach ($userName in $userNames)
    {
        saveConfig $userName "mod" $mod.Trim()
    }

    Write-Host "`n�޸����"
    Read-host "����س�����..."
}

function updateFullScreen($userNames)
{
    $fullScreenConfigs = @("1", "")
    Write-Host "`n"
    Do
    {
        $fullScreen = Read-Host "�Ƿ�ȫ��������Ϸ��ѡ������:

    [1] ��
    [2] ��

��ѡ��ѡ������Ӧ�����"
    }
    while ( !(indexesAllValid $fullScreenConfigs $fullScreen))

    foreach ($userName in $userNames)
    {
        saveConfig $userName "fullScreen" $fullScreenConfigs[$fullScreen - 1]
    }

    Write-Host "`n�޸����"
    Read-host "����س�����..."
}

function update($userNames, $op)
{
    if (![string]::IsNullOrWhiteSpace($userNames))
    {
        if ($userNames -eq "`$0")
        {
            $userNames = $script:userList
        }
        else
        {
            $userNames = $userNames.split(',')
            if (!(validUserName $userNames))
            {
                Write-Host "`n����:��������ȷ���˺�"
                Read-host "����س��˳�..."
                Exit
            }
        }
    }
    else
    {
        showUsersInfo
        Do
        {
            $selectIndexes = Read-Host '��ѡ��Ҫ�޸ĵ��˺ţ������Ӧ��ţ��Կո���������0����ȫѡ��'
        }
        while ($selectIndexes -ne 0 -and !(indexesAllValid $script:userList $selectIndexes))

        $userNames = @()
        if ($selectIndexes -eq 0)
        {
            $userNames = $script:userList
        }
        else
        {
            $selectIndexes.Split(' ') | foreach {
                $userNames += $script:userList[$_ - 1]
            }
        }
    }

    $updateOps = [ordered]@{
        "1" = @("updatePwd", "����")
        "2" = @("updateRegion", "����")
        "3" = @("updateMod", "mod")
        "4" = @("updateFullScreen", "�Ƿ�ȫ������")
    }

    if (![string]::IsNullOrWhiteSpace($op))
    {
        if (!$updateOps.ContainsKey($op))
        {
            Write-Host "`n����:��������ȷ�Ĳ���"
            Read-host "����س��˳�..."
            Exit
        }
    }
    else
    {
        Write-Host "`n"
        Write-Host "���޸ĵ���������:"
        Write-Host "`n"
        $updateOps.GetEnumerator() | ForEach-Object {
            $message = "    [{0}] {1}" -f $_.key, $_.value[1]
            Write-Host "$message"
        }
        Write-Host "`n"
        Do
        {
            $opIndex = Read-Host "��ѡ��ѡ������Ӧ�����:"
        }
        while ( !$updateOps.Contains($opIndex))
        $op = $updateOps[$opIndex][0]
    }

    & $op $userNames
    Write-Host "`n"

    main
}

function startAll
{
    if ($script:userList.Count -gt 0)
    {
        showUsersInfo
        startFromConfig $script:userList
    }
    else
    {
        Write-Host "`n����:��δ��ӹ��˺ţ���������˺�"
        Read-host "����س�����..."
        main
    }
}

function startBatch($userNames)
{
    if ($script:userList.Count -gt 0)
    {
        if (![string]::IsNullOrWhiteSpace($userNames))
        {
            if (!(validUserName $userNames))
            {
                Write-Host "`n����:��������ȷ���˺�"
                Read-host "����س��˳�..."
                Exit
            }
        }
        else
        {
            showUsersInfo
            Do
            {
                $selectIndexes = Read-Host '����������׼���������˺Ŷ�Ӧ����ţ��Կո���'
            }
            while ( !(indexesAllValid $script:userList $selectIndexes))

            $userNames = @()
            $selectIndexes.Split(' ') | foreach {
                $userNames += $script:userList[$_ - 1]
            }
        }

        startFromConfig $userNames
    }
    else
    {
        Write-Host "`n����:��δ��ӹ��˺ţ���������˺�"
        Read-host "����س�����..."
        main
    }
}

function delete($userNames)
{
    if ($script:userList.Count -gt 0)
    {
        if (![string]::IsNullOrWhiteSpace($userNames))
        {
            if (!(validUserName $userNames))
            {
                Write-Host "`n����:��������ȷ���˺�"
                Read-host "����س��˳�..."
                Exit
            }
        }
        else
        {
            showUsersInfo
            Do
            {
                $selectIndexes = Read-Host '����������׼��ɾ�����˺Ŷ�Ӧ����ţ��Կո���'
            }
            while ( !(indexesAllValid $script:userList $selectIndexes))

            $userNames = @()
            $selectIndexes.Split(' ') | foreach {
                $userNames += $script:userList[$_ - 1]
            }
        }

        foreach ($userName in $userNames)
        {
            $userName = $userName.Trim()
            deleteModule $userName
        }

        Write-Host "`nɾ�����"
    }
    else
    {
        Write-Host "`n����:��δ��ӹ��˺�"
    }

    Read-host "����س�����..."
    main
}

function createStartRef($userNames)
{
    if ($script:userList.Count -gt 0)
    {
        if (![string]::IsNullOrWhiteSpace($userNames))
        {
            if (!(validUserName $userNames))
            {
                Write-Host "`n����:��������ȷ���˺�"
                Read-host "����س��˳�..."
                Exit
            }
        }
        else
        {
            showUsersInfo
            Do
            {
                $selectIndexes = Read-Host '����������׼��������ݷ�ʽ�˺Ŷ�Ӧ����ţ��Կո���'
            }
            while ( !(indexesAllValid $script:userList $selectIndexes))

            $userNames = @()
            $selectIndexes.Split(' ') | foreach {
                $userNames += $script:userList[$_ - 1]
            }
        }

        foreach ($userName in $userNames)
        {
            $userName = $userName.trim()
            $wshShell = New-Object -comObject WScript.Shell
            $desktop = [System.Environment]::GetFolderPath('Desktop')
            $shortcut = $wshShell.CreateShortcut("$desktop\$userName.lnk")
            $targetPath = "C:\Windows\System32\cmd.exe"
            $batchPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" startBatch $userName"
            $shortcut.Arguments = "/c $batchPath"
            $shortcut.TargetPath = $targetPath
            $shortcut.IconLocation = "$script:d2rRoot\D2R.exe"
            $shortcut.Save()
        }
        Write-Host "`n������ݷ�ʽ���"
    }
    else
    {
        Write-Host "`n����:��δ��ӹ��˺ţ���������˺�"
    }

    Read-host "����س�����..."
    main
}

function createAllStartRef()
{
    if ($script:userList.Count -gt 0)
    {
        $wshShell = New-Object -comObject WScript.Shell
        $desktop = [System.Environment]::GetFolderPath('Desktop')
        $shortcut = $wshShell.CreateShortcut("$desktop\һ��ȫ������.lnk")
        $targetPath = "C:\Windows\System32\cmd.exe"
        $batchPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" startAll"
        $shortcut.Arguments = "/c $batchPath"
        $shortcut.TargetPath = $targetPath
        $shortcut.IconLocation = "$script:d2rRoot\D2R.exe"
        $shortcut.Save()

        Write-Host "`n����һ��ȫ��������ݷ�ʽ���"
    }
    else
    {
        Write-Host "`n����:��δ��ӹ��˺ţ���������˺�"
    }

    Read-host "����س�����..."
    main
}

function createUpdateAllRegionRef()
{
    if ($script:userList.Count -gt 0)
    {
        $wshShell = New-Object -comObject WScript.Shell
        $desktop = [System.Environment]::GetFolderPath('Desktop')
        $shortcut = $wshShell.CreateShortcut("$desktop\һ���޸ķ���.lnk")
        $targetPath = "C:\Windows\System32\cmd.exe"
        $batchPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" updateRegion `$0"
        $shortcut.Arguments = "/c $batchPath"
        $shortcut.TargetPath = $targetPath
        $shortcut.IconLocation = "$script:d2rRoot\D2R.exe"
        $shortcut.Save()

        Write-Host "`n����һ���޸ķ�����ݷ�ʽ���"
    }
    else
    {
        Write-Host "`n����:��δ��ӹ��˺ţ���������˺�"
    }

    Read-host "����س�����..."
    main
}

function showAllUser
{
    if ($script:userList.Count -gt 0)
    {
        showUsersInfo
    }
    else
    {
        Write-Host "`n��δ��ӹ��˺ţ���������˺�"
    }

    Read-host "����س�����..."
    main
}

function help
{
    Write-Host "`n"
    Write-Host "    ����˵����"
    Write-Host "`n"
    Write-Host "    [1] �״�ʹ�õ�¼������������˺ţ������и����˺���������¼�룻"
    Write-Host "    [2] ��ӻ��޸��˺�ʱ����mod������Я��-txt��׺�����-txt��Ϊmod����һ�����룬�磺hongye -txt��"
    Write-Host "    [3] �����½���ݷ�ʽ�����棬����ѡ��������˺Ÿ���һ����ݷ�ʽ��Ҳ���Խ�һ��һ�����������˺ŵĿ�ݷ�ʽ��"
    Write-Host "    [4] �½������������˺ſ�ݷ�ʽ���ᱻ�������/�޸��˺�������Ӱ�죬ֻҪ�˺Ų�ɾ���Ϳ���һֱʹ�ã�"
    Write-Host "    [5] �½���һ��ȫ��������ݷ�ʽ���ᱻ�������е��˺Ų�����Ӱ�죬¼��������˺žͻ�����������"
    Write-Host "    [6] ����������ԭ���漰���ף�������û�з�ŷ��ա�"

    Write-Host "`n"
    Write-Host "    ��ӯ�����ʹ��ߣ��κη��������ге�"
    Write-Host "`n"

    Read-host "����س�����..."
    main
}

main $operation $param1 $param2

