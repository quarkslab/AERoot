![Python version](https://img.shields.io/badge/Python-%E2%89%A53.7-brightgreen?style=flat-square&logo=python "Python 3")
![Linux](https://img.shields.io/badge/Linux-x86__64-brightgreen?style=flat-square&logo=linux "Linux")
![macOS](https://img.shields.io/badge/macOS-x86__64-brightgreen?style=flat-square&logo=apple "macOS")

![AERoot](https://user-images.githubusercontent.com/56136693/121723563-f4021c80-cae6-11eb-84bb-ac6d6dc32665.png "AERoot Logo")

**AERoot** is a command line tool that allows you to give the root privileges on-the-fly to any process running on the Android emulator with Google Play flavors AVDs.
> This project is a rewrite from scratch of the **android-emuroot** tool (https://github.com/airbus-seclab/android_emuroot).
> It comes with new features:
> * Recent AVDs support (Android API > 27)
> * Execution time optimization
> * Selection of a process by its PID

# Compatible Kernels

| Kernel                                            | x86    | x86_64 | Android version       |
|---------------------------------------------------|:------:|:------:|-----------------------|
| 3.10.0+                                           | ✓      |        | 7.0/7.1 (Google Play) |
| 3.18.56+                                          | ✓      |        | 8.0 (Google Play)     |
| 3.18.91+                                          | ✓      |        | 8.1 (Google Play)     |
| 4.4.124+                                          | ✓      | ✓      | 9.0 (Google Play)     |
| 4.14.112+                                         | ✓      | ✓      | 9.0 (Google Play)     |
| 5.4.36-00815-g3b29042c17b1                        | ✓      | ✓      | 10.0 (Google Play)    |
| 5.4.43-00621-g90087296b3b1                        | ✓      | ✓      | 10.0 (Google Play)    |
| 5.4.47-01061-g22e35a1de440                        | ✓      | ✓      | 10.0 (Google Play)    |
| 5.4.54-android11-0-00619-g476c942d9b3e-ab6722723  | ✓      | ✓      | 11.0 (Google Play)    |
| 5.4.61-android11-0-00791-gbad091cc4bf3-ab6833933  | ✓      | ✓      | 11.0 (Google Play)    |
| 5.4.61-android11-2-00064-g4271ad6e8ade-ab6991359  |        | ✓      | 11.0 (Google Play)    |
| 5.10.4-android12-0-03442-gf2684370d34d-ab7068937  |        | ✓      | 12.0 (Google Play)    |
| 5.10.15-android12-0-01814-gfca78df78ef2-ab7137072 |        | ✓      | 12.0 (Google Play)    |
| 5.10.21-android12-0-01012-gcc574f0d3698-ab7214561 |        | ✓      | 12.0 (Google Play)    |
| 5.10.21-android12-0-01145-ge82381ad9a3f-ab7230153 |        | ✓      | 12.0 (Google Play)    |
| 5.10.35-android12-4-00865-gd9d0c09e0a3b-ab7349034 |        | ✓      | 12.0 (Google Play)    |
| 5.10.43-android12-6-00231-g54e7412d4ff9-ab7460289 |        | ✓      | 12.0 (Google Play)    |

# Requirements

AERoot requires [gdb](https://www.gnu.org/software/gdb/) (with Python support enabled) to run properly.

# Installation

## Last Release

```bash
pip install aeroot
```

## Current version

```bash
git clone https://github.com/quarkslab/AERoot.git
```

```bash
python3 setup.py install --user
```

## Docker

A Docker image of *AERoot* is available on [dockerhub](https://hub.docker.com/r/ha0ris/aeroot).

### Linux

#### Usage

```bash
docker run --network host ha0ris/aeroot [aeroot options]
```

#### Example

```bash
docker run --network host ha0ris/aeroot daemon
```

### macOS

#### Usage

```bash
docker run ha0ris/aeroot --host host.docker.internal [aeroot options]
```

#### Example

```bash
docker run ha0ris/aeroot --host host.docker.internal daemon
```

# Quick-start

First of all, you must launch the Android emulator with the gdb qemu option (`-qemu -s`).
```bash
emulator @Your_AVD -qemu -s
```

Then run **aeroot** by choosing the mode among:
* **pid**: give the root privileges to a process selected by its *PID*.
* **name**: give the root privileges to a process selected by its *name*.
* **daemon**: give the root privileges to the ADB daemon, so shells created with adb shell will automaticaly have root rigths.

## Usage

```bash
aeroot [-h] [--verbose | --quiet] [--device DEVICE] [--host HOST] [--port PORT] {name,pid,daemon} ...
```

## Examples

### *pid* mode example

```bash
aeroot pid 1337
```

> Gives the root privileges to the process with pid 1337

### *name* mode example

```bash
aeroot name my_process
```

> Gives the root privileges to the process named "my_process"

### *daemon* mode example

```bash
aeroot daemon
```

> Gives the root privileges to the ADB daemon

## Additional options

You can find additional options by checking the help of the tool: `aeroot -h`
