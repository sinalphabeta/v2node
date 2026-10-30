# bash completion for the v2node management script
_v2node() {
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "start stop restart status enable disable log update config generate install uninstall version update_shell" -- "${cur}") )
    fi
}

complete -F _v2node v2node
