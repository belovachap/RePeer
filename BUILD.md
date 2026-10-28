# Building RePeer

## Install Dependencies

```bash
sudo apt install git
sudo apt install build-essential libtool autotools-dev automake pkg-config bsdmainutils python3
sudo apt install libevent-dev libboost-dev libssl-dev
sudo apt install libsqlite3-dev
sudo apt install systemtap-sdt-dev
sudo apt install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools
sudo apt install qtwayland5
sudo apt install libqrencode-dev
```
## Get Code

```bash
git clone --recurse-submodules https://github.com/belovachap/RePeer.git
cd RePeer
```

## Build

```bash
./autogen.sh
./configure
make # use "-j N" for N parallel jobs
```
