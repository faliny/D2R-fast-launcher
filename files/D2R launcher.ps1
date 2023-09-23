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
    "kr" = "亚服"
    "eu" = "欧服"
    "us" = "美服"
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
        Write-Host "`n错误:请将脚本和登录管理器等文件放置在D2R安装目录，和D2R.exe在同一个文件夹下。"
        Read-host "点击回车退出..."
        Exit
    }

    if (![System.IO.File]::Exists("$PSScriptRoot\handle64.exe"))
    {
        Write-Host "`n错误:请下载handle64.exe并放置在D2R安装目录，和D2R.exe在同一个文件夹下。下载地址: https://docs.microsoft.com/en-us/sysinternals/downloads/handle"
        Read-host "点击回车退出..."
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
    Write-Host "`n所有账号信息如下：`n"
    $num = 1
    $script:userInfoMap.GetEnumerator() | ForEach-Object {
        $fullScreen = $_.value["fullScreen"]
        if ([string]::IsNullOrWhiteSpace($fullScreen) -or $fullScreen -ne "1")
        {
            $fullScreen = "否"
        }
        else
        {
            $fullScreen = "是"
        }

        $message = "    [{0}] 用户名：{1,-25} 服区：{2,-4} Mod名称：{3,-15} 是否全屏：{4,-2}" -f $num++, $_.key, $script:regionDescMap[$_.value["region"]], $_.value["mod"], $fullScreen
        Write-Host $message
    }
    Write-Host "`n"
}

function showRegions
{
    Write-Host "`n服区信息如下："
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

# 格式：userName,password,region,mod
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
        Write-Host "`n启动游戏，当前账号：$startUser"
        Write-Host "启动过程中可以随时通过同时按下 Ctrl + C 终止启动。"

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
        Write-Host "`n该账号已存在"
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
            Write-Host "`n请选择一个操作，输入对应的序号："
            Write-Host "
    [1]  启动所有账号
    [2]  启动所有指定账号
    [3]  展示所有账号
    [4]  添加账号
    [5]  修改账号
    [6]  删除账号
    [7]  创建单个账号启动快捷方式到桌面
    [8]  创建一键启动所有账号快捷方式到桌面
    [0]  帮助
    `n"

            $op = Read-Host '请输入操作对应的序号'
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
        Write-Host "`n错误:请输入正确的操作类型。"
        Read-host "点击回车退出..."
        Exit
    }
}

function add()
{
    Write-Host "`n"
    Do
    {
        $userName = Read-Host '请输入准备添加的账号'
    }
    while ( [string]::IsNullOrWhiteSpace($userName) -or (checkExist $userName) )

    Do
    {
        $password = Read-Host '请输入账号对应的密码' -AsSecureString
    }
    while ( [string]::IsNullOrWhiteSpace($password))

    $password = $password | ConvertFrom-SecureString

    showRegions

    Do
    {
        $regionIndex = Read-Host '请选择服区，输入对应的序号'
    }
    while ( !(indexesAllValid $script:regionList $regionIndex))

    Write-Host "`n"
    $mod = Read-Host '请输入mod名称，名称取战网配置里-mod之后的所有信息，不使用mod可直接按回车'

    $fullScreenConfigs = @("1", "")
    Do
    {
        Write-Host "`n"
        $fullScreen = Read-Host '是否全屏启动游戏，选项如下:
    [1] 是
    [2] 否
请选择选项，输入对应的序号'
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

    Write-Host "`n添加/修改成功"
    $tmp = Read-host "点击回车继续..."
    main
}

function update()
{
    showUsersInfo
    Do
    {
        $selectIndexes = Read-Host '请选择准备修改的账号，输入对应的序号'
    }
    while ( !(indexesAllValid $script:userList $selectIndexes))

    $userName = $script:userList[$selectIndexes - 1]
    Write-Host "`n"

    $ops = @(1, 2, 3, 4)
    Do
    {
        $op = Read-Host '请选择要修改的内容:
    [1] 密码
    [2] 服区
    [3] mod
    [4] 是否全屏启动
请选择选项，输入对应的序号'
    }
    while ( !(indexesAllValid $ops $op))

    Write-Host "`n"
    if ($op -eq 1)
    {
        Do
        {
            $password = Read-Host '请输入新的密码' -AsSecureString
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
            $regionIndex = Read-Host '请选择服区，输入对应的序号'
        }
        while ( !(indexesAllValid $script:regionList $regionIndex))
        $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "region", $script:regionList[$regionIndex - 1], $script:userInfoFilePath)
    }
    elseif ($op -eq 3)
    {
        $mod = Read-Host '请输入mod名称，名称取战网配置里-mod之后的所有信息，改成不使用直接按回车'
        $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "mod", $mod.Trim(), $script:userInfoFilePath)
    }
    elseif ($op -eq 4)
    {
        $fullScreenConfigs = @("1", "")
        Do
        {
            $fullScreen = Read-Host '是否全屏启动游戏，选项如下:
    [1] 是
    [2] 否
请选择选项，输入对应的序号'
        }
        while ( !(indexesAllValid $fullScreenConfigs $fullScreen))
        $null = [System.Text.WinApi]::WritePrivateProfileString($userName, "fullScreen", $fullScreenConfigs[$fullScreen - 1], $script:userInfoFilePath)
    }

    Write-Host "`n修改完成"
    $tmp = Read-host "点击回车继续..."
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
        Write-Host "`n错误:还未添加过账号，请先添加账号"
        Read-host "点击回车继续..."
        main
    }
}

# 格式：userName1,userName2...
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
                Write-Host "`n错误:请输入正确的启动账号"
                Read-host "点击回车退出..."
                Exit
            }
        }
        else
        {
            showUsersInfo
            Do
            {
                $selectIndexes = Read-Host '请输入所有准备启动的账号对应的序号，以空格间隔'
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
        Write-Host "`n错误:还未添加过账号，请先添加账号"
        Read-host "点击回车继续..."
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
                $selectIndexes = Read-Host '请输入所有准备删除的账号对应的序号，以空格间隔'
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

        Write-Host "`n删除完成"
    }
    else
    {
        Write-Host "`n错误:还未添加过账号"
    }

    Read-host "点击回车继续..."
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
                Write-Host "`n错误:请输入正确的账号"
                Read-host "点击回车退出..."
                Exit
            }
        }
        else
        {
            showUsersInfo
            Do
            {
                $selectIndexes = Read-Host '请输入所有准备创建快捷方式账号对应的序号，以空格间隔'
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
        Write-Host "`n创建快捷方式完成"
    }
    else
    {
        Write-Host "`n错误:还未添加过账号，请先添加账号"
    }

    Read-host "点击回车继续..."
    main
}

function createBatchRef()
{
    if ($script:userList.Count -gt 0)
    {
        $wshShell = New-Object -comObject WScript.Shell
        $desktop = [System.Environment]::GetFolderPath('Desktop')
        $shortcut = $wshShell.CreateShortcut("$desktop\一键全部启动.lnk")
        $targetPath = "C:\Windows\System32\cmd.exe"
        $batchPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" 1"
        $shortcut.Arguments = "/c $batchPath"
        $shortcut.TargetPath = $targetPath
        $shortcut.IconLocation = "$PSScriptRoot\D2R.exe"
        $shortcut.Save()

        Write-Host "`n创建一键全部启动快捷方式完成"
    }
    else
    {
        Write-Host "`n错误:还未添加过账号，请先添加账号"
    }

    Read-host "点击回车继续..."
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
        Write-Host "`n还未添加过账号，请先添加账号"
    }

    Read-host "点击回车继续..."
    main
}

function help
{
    Write-Host "`n"
    Write-Host "    帮助说明：`n"
    Write-Host "    [1] 首次使用登录器，请先添加账号，把所有个人账号配置依次录入；"
    Write-Host "    [2] 添加或修改账号时，若mod配置需携带-txt后缀，则把-txt作为mod名字一并填入，如：hongye -txt；"
    Write-Host "    [3] 对于新建快捷方式到桌面，可以选择把所有账号各建一个快捷方式，也可以建一个一键启动所有账号的快捷方式；"
    Write-Host "    [4] 新建的启动单个账号快捷方式不会被后续添加/修改账号配置所影响，只要账号不删除就可以一直使用；"
    Write-Host "    [5] 新建的一键全部启动快捷方式不会被后续所有的账号操作所影响，录入过几个账号就会启动几个；"
    Write-Host "    [6] 本启动器的原理不涉及作弊，理论上没有封号风险。"

    Write-Host "`n"
    Write-Host "    非盈利性质工具，任何风险请自行承担"
    Write-Host "`n"

    Read-host "点击回车继续..."
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
