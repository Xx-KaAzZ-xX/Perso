#/bin/bash

##Install RTL88x2bu driver on debian based distro

apt-get install bc -y
git clone https://github.com/cilynx/rtl88x2bu.git
cd rlt88x2bu
VER=$(sed -n 's/\PACKAGE_VERSION="\(.*\)"/\1/p' dkms.conf)
rsync -rvhP ./ /usr/src/rtl88x2bu-${VER}
apt-get install -y dkms
dkms add -m rtl88x2bu -v ${VER}
dkms build -m rtl88x2bu -v ${VER}
dkms install -m rtl88x2bu -v ${VER}
modprobe 88x2bu

exit 0
