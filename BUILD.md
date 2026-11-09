# Building RePeer

## Install Dependencies

TODO: Determine that minimum number of depencies needed to install...

```bash
sudo apt install git \
                 cmake \
                 ninja-build \
                 libboost-dev \
                 libssl-dev \
                 libsqlite3-dev \
                 systemtap-sdt-dev \
                 qt6-base-dev \
                 libqrencode-dev
```

## Get Code

```bash
git clone --recurse-submodules https://github.com/belovachap/RePeer.git
cd RePeer
```

## Build

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
cmake --build . -j$(nproc)
```

