# HxGamePatch

针对新版加密方式的krkr游戏设计的补丁 

## 功能

* 过完整性验证（Malformed exe/dll） 

* 取消steam.tjs加载（针对steam平台发行的游戏） 

* 文件补丁功能（使用zip格式，方便打包） 

## 使用方法

编辑config.ini来影响补丁的某些行为，需要注意，config.ini必须为`utf-8无签名`编码  

下为一个示例config.ini的内容: 

```ini
[StartupSettings]
# 想要注入的主程序名称，必须位于当前目录下
Target = ambitious_mission.exe
[PatchSettings]
# 开启命令行窗口用于输出Debug信息（例如补丁文件加载信息）
DebugWindow = false
# 开启文件补丁功能
EnableFilePatch = false
# 补丁文件加载回显
PatchFileEcho = false
# 你想要添加的封包名称，多个封包间以英文逗号分隔
PatchPacks = update.zip,update2.zip
# 开启补丁更新
EnableUpdate = false
# 补丁文件更新回显
UpdateFileEcho = true
# 对已添加的封包内的文件进行覆盖，格式：(想要覆盖的封包名称):(覆盖它的封包名称)
# 你也可以同时在覆盖封包内添加新的文件
UpdatePacks = update.zip:staff.zip,update2.zip:imgs.zip
# 当你在zip封包中放入一个大小为0KB的文件时，补丁将会在当前目录下的此文件夹中寻找同名文件并打开
# 推荐在文件体积超过20MB时使用，此举可以有效减少内存占用
ExternalPath = chs_ext
```

## 致谢

[libzippp](https://github.com/ctabin/libzippp)

[Leksys' INI Parser](https://github.com/Lek-sys/LeksysINI)

## 有其它问题？

欢迎提issue

#      

# HxGamePatch

Designed for new krkr games which uses "hx" encryption method. 

## Features

* Bypass consistency check (e.g. Malformed exe/dll) 

* Bypass steam.tjs for some steam games 

* File patch uses zip file format 

## Usage

You can change the patch's behavior by editing config.ini. (Notice that config.ini must be `utf-8` encoded) 

Here is an example: 

```ini
[StartupSettings]
# The main executable you want to inject the dll into
Target = ambitious_mission.exe
[PatchSettings]
# Enable the CommandPrompt Window for debug
DebugWindow = false
EnableFilePatch = false
# Output FilePatch details to CONOUT$
PatchFileEcho = false
# Packs you want dll to add, split by ','
PatchPacks = update.zip,update2.zip
EnableUpdate = false
UpdateFileEcho = true
# Override file inside packs, format: (original pack):(override pack), ...
# You can add new files while overriding other files
UpdatePacks = update.zip:staff.zip,update2.zip:imgs.zip
# If you add a 0KB file to the pack, dll will try to open it in this folder in the current directory.
# Recommended when the file size is larger than 20MB in order to reduce memory usage
ExternalPath = chs_ext
```

## Thanks

[libzippp](https://github.com/ctabin/libzippp)

[Leksys' INI Parser](https://github.com/Lek-sys/LeksysINI)

## Need Help?

Feel free to ask any questions you have. 

