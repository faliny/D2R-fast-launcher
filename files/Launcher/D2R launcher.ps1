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
    "kr" = "亚服"
    "eu" = "欧服"
    "us" = "美服"
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
        Write-Host "`n错误:请将快捷登录器文件夹放置在D2R根目录下"
        Read-host "点击回车退出..."
        Exit
    }

    if (![System.IO.File]::Exists("$PSScriptRoot\handle64.exe"))
    {
        Write-Host "`n错误:请下载handle64.exe并放置在D2R根目录的Launcher文件夹下，和脚本在同一个文件夹。下载地址: https://docs.microsoft.com/en-us/sysinternals/downloads/handle"
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
        Write-Host "`n启动游戏，当前账号：$userName"
        Write-Host "启动过程中可以随时通过同时按下 Ctrl + C 终止启动"

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
        Write-Host "`n该账号已存在"
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
            "1" = @("startAll", "启动所有账号")
            "2" = @("startBatch", "启动所有指定账号")
            "3" = @("showAllUser", "展示所有账号")
            "4" = @("add", "添加账号")
            "5" = @("update", "修改账号")
            "6" = @("delete", "删除账号")
            "7" = @("createStartRef", "创建单个账号启动快捷方式到桌面")
            "8" = @("createAllStartRef", "创建一键启动全部账号快捷方式到桌面")
            "9" = @("createUpdateAllRegionRef", "创建一键修改全部账号服区快捷方式到桌面")
            "0" = @("help", "帮助")
        }

        Write-Host "`n请选择一个操作，输入对应的序号：`n"
        $mainOps.GetEnumerator() | ForEach-Object {
            $message = "    [{0}] {1}" -f $_.key, $_.value[1]
            Write-Host "$message"
        }
        Write-Host "`n"

        Do
        {
            $opIndex = Read-Host '请输入操作对应的序号'
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
        Write-Host "`n错误:请输入正确的操作类型"
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
    saveConfig $userName "password" $userInfo["password"]
    saveConfig $userName "region" $userInfo["region"]
    saveConfig $userName "mod" $userInfo["mod"]
    saveConfig $userName "fullScreen" $userInfo["fullScreen"]

    Write-Host "`n添加/修改成功"
    Read-host "点击回车继续..."
    main
}

function updatePwd($userNames)
{
    Do
    {
        $password = Read-Host '请输入新的密码' -AsSecureString
    }
    while ( [string]::IsNullOrWhiteSpace($password))

    $password = $password | ConvertFrom-SecureString

    foreach ($userName in $userNames)
    {
        saveConfig $userName "password" $password
    }

    Write-Host "`n修改完成"
    Read-host "点击回车继续..."
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
        $regionIndex = Read-Host '请选择服区，输入对应的序号'
    }
    while ( !(indexesAllValid $script:regionList $regionIndex))

    foreach ($userName in $userNames)
    {
        saveConfig $userName "region" $script:regionList[$regionIndex - 1]
    }

    Write-Host "`n修改完成"
    Read-host "点击回车继续..."
}

function updateMod($userNames)
{
    $mod = Read-Host '请输入mod名称，名称取战网配置里-mod之后的所有信息，想删除mod直接按回车'

    foreach ($userName in $userNames)
    {
        saveConfig $userName "mod" $mod.Trim()
    }

    Write-Host "`n修改完成"
    Read-host "点击回车继续..."
}

function updateFullScreen($userNames)
{
    $fullScreenConfigs = @("1", "")
    Write-Host "`n"
    Do
    {
        $fullScreen = Read-Host "是否全屏启动游戏，选项如下:

    [1] 是
    [2] 否

请选择选项，输入对应的序号"
    }
    while ( !(indexesAllValid $fullScreenConfigs $fullScreen))

    foreach ($userName in $userNames)
    {
        saveConfig $userName "fullScreen" $fullScreenConfigs[$fullScreen - 1]
    }

    Write-Host "`n修改完成"
    Read-host "点击回车继续..."
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
                Write-Host "`n错误:请输入正确的账号"
                Read-host "点击回车退出..."
                Exit
            }
        }
    }
    else
    {
        showUsersInfo
        Do
        {
            $selectIndexes = Read-Host '请选择要修改的账号，输入对应序号，以空格间隔（输入0代表全选）'
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
        "1" = @("updatePwd", "密码")
        "2" = @("updateRegion", "服区")
        "3" = @("updateMod", "mod")
        "4" = @("updateFullScreen", "是否全屏启动")
    }

    if (![string]::IsNullOrWhiteSpace($op))
    {
        if (!$updateOps.ContainsKey($op))
        {
            Write-Host "`n错误:请输入正确的操作"
            Read-host "点击回车退出..."
            Exit
        }
    }
    else
    {
        Write-Host "`n"
        Write-Host "可修改的内容如下:"
        Write-Host "`n"
        $updateOps.GetEnumerator() | ForEach-Object {
            $message = "    [{0}] {1}" -f $_.key, $_.value[1]
            Write-Host "$message"
        }
        Write-Host "`n"
        Do
        {
            $opIndex = Read-Host "请选择选项，输入对应的序号:"
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
        Write-Host "`n错误:还未添加过账号，请先添加账号"
        Read-host "点击回车继续..."
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
                $selectIndexes = Read-Host '请输入所有准备启动的账号对应的序号，以空格间隔'
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
            if (!(validUserName $userNames))
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
            deleteModule $userName
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

function createStartRef($userNames)
{
    if ($script:userList.Count -gt 0)
    {
        if (![string]::IsNullOrWhiteSpace($userNames))
        {
            if (!(validUserName $userNames))
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
        Write-Host "`n创建快捷方式完成"
    }
    else
    {
        Write-Host "`n错误:还未添加过账号，请先添加账号"
    }

    Read-host "点击回车继续..."
    main
}

function createAllStartRef()
{
    if ($script:userList.Count -gt 0)
    {
        $wshShell = New-Object -comObject WScript.Shell
        $desktop = [System.Environment]::GetFolderPath('Desktop')
        $shortcut = $wshShell.CreateShortcut("$desktop\一键全部启动.lnk")
        $targetPath = "C:\Windows\System32\cmd.exe"
        $batchPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" startAll"
        $shortcut.Arguments = "/c $batchPath"
        $shortcut.TargetPath = $targetPath
        $shortcut.IconLocation = "$script:d2rRoot\D2R.exe"
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

function createUpdateAllRegionRef()
{
    if ($script:userList.Count -gt 0)
    {
        $wshShell = New-Object -comObject WScript.Shell
        $desktop = [System.Environment]::GetFolderPath('Desktop')
        $shortcut = $wshShell.CreateShortcut("$desktop\一键修改服区.lnk")
        $targetPath = "C:\Windows\System32\cmd.exe"
        $batchPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" updateRegion `$0"
        $shortcut.Arguments = "/c $batchPath"
        $shortcut.TargetPath = $targetPath
        $shortcut.IconLocation = "$script:d2rRoot\D2R.exe"
        $shortcut.Save()

        Write-Host "`n创建一键修改服区快捷方式完成"
    }
    else
    {
        Write-Host "`n错误:还未添加过账号，请先添加账号"
    }

    Read-host "点击回车继续..."
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
        Write-Host "`n还未添加过账号，请先添加账号"
    }

    Read-host "点击回车继续..."
    main
}

function help
{
    Write-Host "`n"
    Write-Host "    帮助说明："
    Write-Host "`n"
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

main $operation $param1 $param2

