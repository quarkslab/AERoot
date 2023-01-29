![Python version](https://img.shields.io/badge/Python-%E2%89%A53.7-brightgreen?style=flat-square&logo=python "Python 3")
![Linux](https://img.shields.io/badge/Linux-x86__64-brightgreen?style=flat-square&logo=linux "Linux")
![macOS](https://img.shields.io/badge/macOS-x86__64-brightgreen?style=flat-square&logo=apple "macOS")
[![Codestyle](https://img.shields.io/badge/codestyle-black-000000?style=flat-square)](https://github.com/psf/black)

![AERoot](https://user-images.githubusercontent.com/56136693/121723563-f4021c80-cae6-11eb-84bb-ac6d6dc32665.png "AERoot Logo")

**AERoot** is a command line tool that allows you to give the root privileges on-the-fly to any process running on the Android emulator with Google Play flavors AVDs.
> This project is a rewrite from scratch of the **android-emuroot** tool (https://github.com/airbus-seclab/android_emuroot).
> It comes with new features:
> * Recent AVDs support (Android API > 27)
> * Execution time optimization
> * Selection of a process by its PID

# Compatible Kernels

| Kernel                                             | x86    | x86_64 | Android version              |
|----------------------------------------------------|:------:|:------:|------------------------------|
| 3.10.0+                                            | ✓      |        | 7.0 / 7.1                    |
| 3.18.56+                                           | ✓      |        | 8.0                          |
| 3.18.91+                                           | ✓      |        | 8.1                          |
| 4.4.124+                                           | ✓      | ✓      | 9.0                          |
| 4.14.112+                                          | ✓      | ✓      | 9.0 + 10.0 (TV / Automotive) |
| 5.4.36-00815-g3b29042c17b1                         | ✓      | ✓      | 10.0                         |
| 5.4.43-00621-g90087296b3b1                         | ✓      | ✓      | 10.0                         |
| 5.4.47-01061-g22e35a1de440                         | ✓      | ✓      | 10.0                         |
| 5.4.54-android11-0-00619-g476c942d9b3e-ab6722723   | ✓      | ✓      | 11.0                         |
| 5.4.61-android11-0-00791-gbad091cc4bf3-ab6833933   | ✓      | ✓      | 11.0                         |
| 5.4.61-android11-2-00064-g4271ad6e8ade-ab6991359   |        | ✓      | 11.0                         |
| 5.4.86-android11-2-00006-gae78026f427c-ab7595864   |        | ✓      | 11.0 (Automotive)            |
| 5.4.86-android11-2-00040-g29b2beadc627-ab7157994   | ✓      | ✓      | 11.0 (TV / Automotive)       |
| 5.10.4-android12-0-03442-gf2684370d34d-ab7068937   |        | ✓      | 12.0                         |
| 5.10.15-android12-0-01814-gfca78df78ef2-ab7137072  |        | ✓      | 12.0                         |
| 5.10.21-android12-0-01012-gcc574f0d3698-ab7214561  |        | ✓      | 12.0                         |
| 5.10.21-android12-0-01145-ge82381ad9a3f-ab7230153  |        | ✓      | 12.0                         |
| 5.10.35-android12-4-00865-gd9d0c09e0a3b-ab7349034  |        | ✓      | 12.0                         |
| 5.10.43-android12-6-00231-g54e7412d4ff9-ab7460289  |        | ✓      | 12.0                         |
| 5.10.43-android12-9-00001-ga30f38980440-ab7882141  |        | ✓      | 12.0                         |
| 5.10.66-android12-9-00022-g2d6a43c0364d-ab7992900  | ✓      |        | 12.0 (TV)                    |
| 5.10.66-android12-9-00041-gfa9c9074531e-ab7914766  |        | ✓      | 12.0                         |
| 5.10.102-android13-0-00549-g255b30f804ac-ab8238117 | ✓      | ✓      | 13.0 + 13.0 (TV)             |
| 5.10.107-android13-2-00451-g7ba447d0399b-ab8409457 |        | ✓      | 13.0                         |
| 5.15.32-android13-3-00067-g7b5e736d7c63-ab8474665  |        | ✓      | 13.0                         |
| 5.15.41-android13-6-02245-g158384f20d1e-ab8610100  |        | ✓      | 13.0                         |
| 5.15.41-android13-8-00205-gf1bf82c3dacd-ab8747247  |        | ✓      | 13.0                         |
| 5.15.41-android13-8-00055-g4f5025129fe8-ab8949913  |        | ✓      | 13.0                         |

# Requirements

AERoot requires [gdb](https://www.gnu.org/software/gdb/) (with Python support enabled) to run properly.

# Installation

## Last Release

```console
pip install aeroot
```

## Current version

```console
git clone https://github.com/quarkslab/AERoot.git
```

```console
python3 setup.py install --user
```

## Docker

A Docker image of *AERoot* is available on [dockerhub](https://hub.docker.com/r/ha0ris/aeroot).

Also, you can build an image by yourself:
```console
docker build -t aeroot https://github.com/quarkslab/AERoot.git
```

### Linux

#### Usage

```console
docker run --rm \
           -v $HOME/.emulator_console_auth_token:$HOME/.emulator_console_auth_token \
           --network host \
           ha0ris/aeroot [aeroot options]
```

#### Example

```console
docker run --rm \
           -v $HOME/.emulator_console_auth_token:$HOME/.emulator_console_auth_token \
           --network host \
           ha0ris/aeroot daemon
```

### macOS

#### Usage

```console
docker run --rm \
           -v $HOME/.emulator_console_auth_token:$HOME/.emulator_console_auth_token \
           ha0ris/aeroot --host host.docker.internal [aeroot options]
```

#### Example

```console
docker run --rm \
           -v $HOME/.emulator_console_auth_token:$HOME/.emulator_console_auth_token \
           ha0ris/aeroot --host host.docker.internal daemon
```

# Quick-start

First of all, you must launch the Android emulator with the gdb qemu option (`-qemu -s`).
```console
emulator @Your_AVD -qemu -s
```

Then run **aeroot** by choosing the mode among:
* **pid**: give the root privileges to a process selected by its *PID*.
* **name**: give the root privileges to a process selected by its *name*.
* **daemon**: give the root privileges to the ADB daemon, so shells created with adb shell will automaticaly have root rigths.

## Usage

```console
aeroot [-h] [--verbose | --quiet] [--device DEVICE] [--host HOST] [--port PORT] {name,pid,daemon} ...
```

## Examples

### *pid* mode example

```console
aeroot pid 1337
```

> Gives the root privileges to the process with pid 1337

### *name* mode example

```console
aeroot name my_process
```

> Gives the root privileges to the process named "my_process"

### *daemon* mode example

```console
aeroot daemon
```

> Gives the root privileges to the ADB daemon

## Additional options

You can find additional options by checking the help of the tool: `aeroot -h`
