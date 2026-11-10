# Building RePeer

## Install Dependencies

```bash
sudo apt install git \
                 cmake \
                 ninja-build \
                 build-essential \
                 pkg-config \
                 libssl-dev \
                 libsqlite3-dev \
                 libboost-dev \
                 qt6-base-dev
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

