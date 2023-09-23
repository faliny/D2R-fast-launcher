#== D2R multiclient transparent launcher by Chobot - https://github.com/Chobotz/D2R-multiclient-tools =====
#== Update to D2R fast launcher by faliny - https://github.com/faliny/D2R-fast-launcher =====

param($operation, $param)

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
$script:allOperation = @{ }
$script:buff = New-Object System.Text.StringBuilder(1024)

function init
{
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
    {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $operation $param" -Verb RunAs; exit
    }

    if (![System.IO.File]::Exists("$PSScriptRoot\D2R.exe"))
    {
        Write-Host "`n����:�뽫�ű��͵�¼���������ļ�������D2R��װĿ¼����D2R.exe��ͬһ���ļ����¡�"
        Read-host "����س��˳�..."
        Exit
    }

    if (![System.IO.File]::Exists("$PSScriptRoot\handle64.exe"))
    {
        Write-Host "`n����:������handle64.exe��������D2R��װĿ¼����D2R.exe��ͬһ���ļ����¡����ص�ַ: https://docs.microsoft.com/en-us/sysinternals/downloads/handle"
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
            $null = [System.Text.WinApi]::GetPrivateProfileString($user, "password", "", $script:buff, $script:buff.Capacity, $script:userInfoFilePath)
            $password = $script:buff.tostring()
            if ( [string]::IsNullOrWhiteSpace($password))
            {
                continue
            }
            $userInfo = @{ "password" = $password }

            $null = [System.Text.WinApi]::GetPrivateProfileString($user, "region", "", $script:buff, $script:buff.Capacity, $script:userInfoFilePath)
            $region = $script:buff.tostring()
            if ( [string]::IsNullOrWhiteSpace($region))
            {
                $region = "$defaultRegion"
            }
            $userInfo.add("region", $region)

            $null = [System.Text.WinApi]::GetPrivateProfileString($user, "mod", "", $script:buff, $script:buff.Capacity, $script:userInfoFilePath)
            $mod = $script:buff.tostring()
            if (![string]::IsNullOrWhiteSpace($mod))
            {
                $userInfo.add("mod", $mod)
            }

            $null = [System.Text.WinApi]::GetPrivateProfileString($user, "fullScreen", "", $script:buff, $script:buff.Capacity, $script:userInfoFilePath)
            $fullScreen = $script:buff.tostring()
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

function userNameAllValid($userNames)
{
    try
    {
        $userNames = $userNames.split(',')
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

# ��ʽ��userName,password,region,mod
function validUserInfo($userInfo)
{
    try
    {
        $p = $userInfo.split(',')
        if ($p.Count -lt 3)
        {
            return $false
        }

        if ([string]::IsNullOrWhiteSpace($p[0]) -or [string]::IsNullOrWhiteSpace($p[1]) -or [string]::IsNullOrWhiteSpace($p[2]))
        {
            return $false
        }

        if (!$script:regionDescMap.Contains($p[2]))
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

function startFromConfig($startUserList)
{
    foreach ($startUser in $startUserList)
    {
        $startUser = $startUser.trim()
        Write-Host "`n������Ϸ����ǰ�˺ţ�$startUser"
        Write-Host "���������п�����ʱͨ��ͬʱ���� Ctrl + C ��ֹ������"

        closeHandle

        $password = $script:userInfoMap[$startUser]["password"] | ConvertTo-SecureString
        $cred = New-Object -TypeName System.Management.Automation.PSCredential("JustGiveAName", $password)
        $password = $cred.GetNetworkCredential().Password
        $region = $script:userInfoMap[$startUser]["region"]
        $mod = $script:userInfoMap[$startUser]["mod"]
        $fullScreen = $script:userInfoMap[$startUser]["fullScreen"]

        if ([string]::IsNullOrWhiteSpace($fullScreen) -or $fullScreen -ne "1")
        {
            $fullScreen = "-w"
        }
        else
        {
            $fullScreen = ""
        }

        $p = "-username $startUser -password $password -address $region.actual.battle.net $fullScreen -mod $mod"
        [Array]$p = $p.Split(' ')

        & $PSScriptRoot\D2R.exe $p

        Start-Sleep -Seconds 2
        setWindowName $startUser
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

function main
{
    clear
    init
    if ( [string]::IsNullOrWhiteSpace($operation))
    {
        Do
        {
            Write-Host "`n��ѡ��һ�������������Ӧ����ţ�"
            Write-Host "
    [1]  ���������˺�
    [2]  ��������ָ���˺�
    [3]  չʾ�����˺�
    [4]  ����˺�
    [5]  �޸��˺�
    [6]  ɾ���˺�
    [7]  ���������˺�������ݷ�ʽ������
    [8]  ����һ�����������˺ſ�ݷ�ʽ������
    [0]  ����
    `n"

            $op = Read-Host '�����������Ӧ�����'
        }
        while ( !$script:allOperation.ContainsKey($op))
    }
    else
    {
        $op = $operation
        $operation = $null
    }

    if ( $script:allOperation.ContainsKey($op))
    {
        & $script:allOperation[$op] $param
    }
    else
    {
        Write-Host "`n����:��������ȷ�Ĳ������͡�"
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
    $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "password", $userInfo["password"], $script:userInfoFilePath)
    $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "region", $userInfo["region"], $script:userInfoFilePath)
    $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "mod", $userInfo["mod"], $script:userInfoFilePath)
    $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "fullScreen", $userInfo["fullScreen"], $script:userInfoFilePath)

    Write-Host "`n���/�޸ĳɹ�"
    $tmp = Read-host "����س�����..."
    main
}

function update()
{
    showUsersInfo
    Do
    {
        $selectIndexes = Read-Host '��ѡ��׼���޸ĵ��˺ţ������Ӧ�����'
    }
    while ( !(indexesAllValid $script:userList $selectIndexes))

    $userName = $script:userList[$selectIndexes - 1]
    Write-Host "`n"

    $ops = @(1, 2, 3, 4)
    Do
    {
        $op = Read-Host '��ѡ��Ҫ�޸ĵ�����:
    [1] ����
    [2] ����
    [3] mod
    [4] �Ƿ�ȫ������
��ѡ��ѡ������Ӧ�����'
    }
    while ( !(indexesAllValid $ops $op))

    Write-Host "`n"
    if ($op -eq 1)
    {
        Do
        {
            $password = Read-Host '�������µ�����' -AsSecureString
        }
        while ( [string]::IsNullOrWhiteSpace($password))

        $password = $password | ConvertFrom-SecureString
        $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "password", $password, $script:userInfoFilePath)
    }
    elseif ($op -eq 2)
    {
        showRegions
        Do
        {
            $regionIndex = Read-Host '��ѡ������������Ӧ�����'
        }
        while ( !(indexesAllValid $script:regionList $regionIndex))
        $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "region", $script:regionList[$regionIndex - 1], $script:userInfoFilePath)
    }
    elseif ($op -eq 3)
    {
        $mod = Read-Host '������mod���ƣ�����ȡս��������-mod֮���������Ϣ���ĳɲ�ʹ��ֱ�Ӱ��س�'
        $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "mod", $mod.Trim(), $script:userInfoFilePath)
    }
    elseif ($op -eq 4)
    {
        $fullScreenConfigs = @("1", "")
        Do
        {
            $fullScreen = Read-Host '�Ƿ�ȫ��������Ϸ��ѡ������:
    [1] ��
    [2] ��
��ѡ��ѡ������Ӧ�����'
        }
        while ( !(indexesAllValid $fullScreenConfigs $fullScreen))
        $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "fullScreen", $fullScreenConfigs[$fullScreen - 1], $script:userInfoFilePath)
    }

    Write-Host "`n�޸����"
    $tmp = Read-host "����س�����..."
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

# ��ʽ��userName1,userName2...
function start($selectUsers)
{
    if ($script:userList.Count -gt 0)
    {
        if (![string]::IsNullOrWhiteSpace($selectUsers))
        {
            if (userNameAllValid $selectUsers)
            {
                $selectUsers = $selectUsers.split(',')
            }
            else
            {
                Write-Host "`n����:��������ȷ�������˺�"
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

            $selectUsers = @()
            $selectIndexes.Split(' ') | foreach {
                $selectUsers += $script:userList[$_ - 1]
            }
        }

        startFromConfig $selectUsers
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
            $userNames = $userNames.split(',')
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
            $null = [System.Text.WinApi]::WritePrivateProfileSection($userName, $null, $script:userInfoFilePath)
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

function createRef($selectUsers)
{
    if ($script:userList.Count -gt 0)
    {
        if (![string]::IsNullOrWhiteSpace($selectUsers))
        {
            if (userNameAllValid $selectUsers)
            {
                $selectUsers = $selectUsers.split(',')
            }
            else
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

            $selectUsers = @()
            $selectIndexes.Split(' ') | foreach {
                $selectUsers += $script:userList[$_ - 1]
            }
        }

        foreach ($selectUser in $selectUsers)
        {
            $selectUser = $selectUser.trim()
            $wshShell = New-Object -comObject WScript.Shell
            $desktop = [System.Environment]::GetFolderPath('Desktop')
            $shortcut = $wshShell.CreateShortcut("$desktop\$selectUser.lnk")
            $targetPath = "C:\Windows\System32\cmd.exe"
            $batchPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" 2 $selectUser"
            $shortcut.Arguments = "/c $batchPath"
            $shortcut.TargetPath = $targetPath
            $shortcut.IconLocation = "$PSScriptRoot\D2R.exe"
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

function createBatchRef()
{
    if ($script:userList.Count -gt 0)
    {
        $wshShell = New-Object -comObject WScript.Shell
        $desktop = [System.Environment]::GetFolderPath('Desktop')
        $shortcut = $wshShell.CreateShortcut("$desktop\һ��ȫ������.lnk")
        $targetPath = "C:\Windows\System32\cmd.exe"
        $batchPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" 1"
        $shortcut.Arguments = "/c $batchPath"
        $shortcut.TargetPath = $targetPath
        $shortcut.IconLocation = "$PSScriptRoot\D2R.exe"
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

function show
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
    Write-Host "    ����˵����`n"
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

$script:allOperation = @{
    "1" = (gi function:startAll)
    "2" = (gi function:start)
    "3" = (gi function:show)
    "4" = (gi function:add)
    "5" = (gi function:update)
    "6" = (gi function:delete)
    "7" = (gi function:createRef)
    "8" = (gi function:createBatchRef)
    "0" = (gi function:help)
}

main
