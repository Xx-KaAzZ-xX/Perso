#!/bin/bash


# Custom bashrc
cp /root/.bashrc /root/.bashrc.orig
sed -i 's/^# export LS_OPTIONS=/export LS_OPTIONS=/g' /root/.bashrc
sed -i 's/^# eval "`dircolors`"/eval "`dircolors`"/g' /root/.bashrc
sed -i 's/^# alias ls=/alias ls=/g' /root/.bashrc
sed -i 's/^# alias ll=/alias ll=/g' /root/.bashrc
sed -i 's/^# alias l=/alias l=/g' /root/.bashrc

echo "
alias al=\"ls \$LS_OPTIONS -alh\" 
alias showconnections=\"netstat -ntu | awk '{print \$5}' | cut -d: -f1 | grep -E [0-9.]+ | sort | uniq -c | sort -n\" 
force_color_prompt=\"yes\"
PS1='${debian_chroot:+($debian_chroot)}\[\033[01;95m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
" >> /root/.bashrc

echo "Think do : source /root/.bashrc"

exit 0
