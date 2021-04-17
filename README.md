![Python version](https://img.shields.io/badge/python-3-informational "Python 3")

# AERoot (Android Emulator ROOTing system)
![alt text](img/logo.png "AERoot Logo")
**AERoot** is a command line tool that allows you to give the root privileges on-the-fly to any process running on the Android emulator with Google Play flavors AVDs.
> This project is a rewrite from scratch of the **android-emuroot** tool (https://github.com/airbus-seclab/android_emuroot).
> It comes with new features:
> * Recent AVDs support (Android API > 27)
> * Execution time optimization
> * Selection of a process by its PID

# Compatible AVDs
| Release Name | API Level | ABI    | Target                      |
|--------------|-----------|--------|-----------------------------|
| Nougat       | 24        | x86    | Android 7.0 (Google Play)   |
| Nougat       | 25        | x86    | Android 7.1.1 (Google Play) |
| Oreo         | 26        | x86    | Android 8.0 (Google Play)   |
| Oreo         | 27        | x86    | Android 8.1 (Google Play)   |
| Pie          | 28        | x86    | Android 9.0 (Google Play)   |
| Pie          | 28        | x86_64 | Android 9.0 (Google Play)   |
| Q            | 29        | x86    | Android 10.0 (Google Play)  |
| Q            | 29        | x86_64 | Android 10.0 (Google Play)  |
| R            | 30        | x86    | Android 11.0 (Google Play)  |
| R            | 30        | x86_64 | Android 11.0 (Google Play)  |

# Installation
```bash
git clone https://github.com/quarkslab/AERoot.git
```
```bash
pip3 install -r requirements.txt
```
# Quick-start
First of all, you must launch the Android emulator with the gdb qemu option (-qemu -s).
```bash
emulator @Your_AVD -qemu -s
```

Then run **aeroot.py** by choosing the mode among:
* **pid**: give the root privileges to a process selected by its PID.
* **name**: give the root privileges to a process selected by its name.
* **daemon**: give the root privileges to the ADB daemon, so shells created with adb shell will automaticaly have root rigths.

## Usage
```bash
aeroot.py [-h] [--verbose | --quiet] [--device DEVICE] [--host HOST] [--port PORT] {name,pid,daemon} ...
```

## Examples
### *pid* mode example
```bash
aeroot.py pid 1337
```
> Gives the root privileges to the process with pid 1337
### *name* mode example
```bash
aeroot.py name my_process
```
> Gives the root privileges to the process named "my_process"
### *daemon* mode example
```bash
aeroot.py daemon
```
> Gives the root privileges to the ADB daemon

## Additional options
You can find additional options by checking the help of the tool: `aeroot.py -h`
