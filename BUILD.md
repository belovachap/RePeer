# Building RePeer

## Install Dependencies

```bash
sudo apt install git
sudo apt install build-essential libtool autotools-dev automake pkg-config bsdmainutils
sudo apt install libboost-dev libssl-dev
sudo apt install libsqlite3-dev
sudo apt install systemtap-sdt-dev
sudo apt install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools
sudo apt install qtwayland5
sudo apt install libqrencode-dev
```

sudo apt install nlohmann-json3-dev # for univalue?
sudo apt-get install libgflags-dev # for crc32c?
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

cmake stuff:

```
mkdir build && cd build
cmake .. -DENABLE_WALLET=ON -DENABLE_QT=ON -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
```