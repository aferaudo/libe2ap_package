# libe2ap software package
This repository contains E2AP source files used to build a .deb software packages.

## Build software package

Go in the `e2ap_source` package and run
```bash
./build.sh
```

Copy the `libriclibe2ap.so` and `libriclibe2ap.a` files in the directories `riclibe2ap/usr/local/lib` and `riclibe2ap-dev/usr/local/lib` respectively. In the last case you need to copy also headers.
```bash
cp e2ap_source/output/libriclibe2ap.so riclibe2ap/usr/local/lib/
cp e2ap_source/output/libriclibe2ap.a riclibe2ap-dev/usr/local/lib

# Copying headers
cp e2ap_source/headers/ riclibe2ap-dev/usr/local/include/riclibe2ap
```

Remember to change the version in `DEBIAN/control` file accordingly.

Create `.deb` software package
```bash
dpkg-deb --build riclibe2ap
dpkg-deb --build riclibe2ap-dev
```
