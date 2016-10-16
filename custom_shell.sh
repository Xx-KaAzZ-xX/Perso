#!/bin/bash
apt-get install vim
    if [[ ! -f /etc/vim/vimrc.local ]]; then
        echo -e "syntax on \
            \nset smarttab \
            \nset noet ci pi sts=0 sw=4 ts=4 \
            \nset cursorline \
            \nfiletype plugin indent on \
            \nset t_Co=256 \
            \nset background=dark \
            \nset titlestring=%f title \
            \nset nobk nowb noswf \
            \nset tabstop=2 \
            \nset shiftwidth=2 \
            \nset expandtab \
			\nset mouse=a \
			\nset incsearch
            " > /etc/vim/vimrc.local
        #log "Configuration of Vim in /etc/vim/vimrc.local"
    fi

#Color root Shell
cat >> /root/.bashrc << _EOF_
export LS_OPTIONS='--color=auto'
eval "`dircolors`"
alias ls='ls $LS_OPTIONS'
_EOF_

. /root/.bashrc
echo "Think to do a '. /root/.bashrc' if the modif aren't activated"
exit 0
