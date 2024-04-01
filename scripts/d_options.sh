#!/bin/bash

if command -v recsel >/dev/null 2>&1 ; then : ; else
  echo "Error: The command 'recsel' is missing. Please install recutils." >&2
  exit 1
fi

if command -v recset >/dev/null 2>&1 ; then : ; else
  echo "Error: The command 'recset' is missing. Please install recutils." >&2
  exit 1
fi

if command -v recfmt >/dev/null 2>&1 ; then : ; else
  echo "Error: The command 'recfmt' is missing. Please install recutils." >&2
  exit 1
fi

if (( 0 + 1 )) 2>/dev/null && test "$(( 2 + 2 ))" = "4" 2>/dev/null ; then : ; else
  echo "Error: Built-in shell math is required" >&2
  exit 1
fi

if declare -a ARGS 2>/dev/null ; then : ; else
  echo "Error: Indexed arrays support is required" >&2
  exit 1
fi

# parameters
max_width=79
  
# cut string to given length at word boundary if possible
cut_str_word () {
    local str="$1"
    local len=$2
    declare -g cut_str_word_res=''
    [[ $len -eq 0 ]] && return 1
    if [[ ${#str} -le $len ]]; then
        cut_str_word_res="${str}"
        return 0
    fi
    if [[ "${str:${len}:1}" = " " ]]; then
        cut_str_word_res="${str:0:${len}}"
        return 0
    fi
    cut_str_word_res="${str:0:${len}}"
    cut_str_word_res="${cut_str_word_res% *}"
    return 0
}

format_param_descr() {
    local prefix1="$1" # first line prefix
    local desc="$2"
    local prefix2="$3" # prefix on all other lines
    local width="$4"
    local tmp_str
    declare -g format_param_descr_res=''
    [[ -z $3 ]] && prefix2=' *'
    [[ -z $width ]] && width=79
    prefix1="${prefix1#${prefix1%%[! ]*}}"
    prefix1="${prefix1%${prefix1##*[! ]}} " # trim prefix1
    desc="${desc#${desc%%[! ]*}}"
    desc="${desc%${desc##*[! ]}}" # trim desc
    local width_r=$(( width - ${#prefix1} ))
    local tmp_str="${prefix1//?/ }"
    prefix2="
${prefix2}${tmp_str:${#prefix2}}"
    cut_str_word "$desc" $width_r || return 1
    format_param_descr_res="${prefix1}${cut_str_word_res}"
    desc="${desc:${#cut_str_word_res}}"
    desc="${desc#${desc%%[! ]*}}" # trim leading spaces
    while [[ -n "$desc" ]]; do
        cut_str_word "$desc" $width_r || return 1
        format_param_descr_res+="${prefix2}${cut_str_word_res}"
        desc="${desc:${#cut_str_word_res}}"
    done
    return 0
}


cp d_options.rec tmp.rec || exit 2

for N in $(recsel -t MHD_Option -R Value d_options.rec)
do
    NAME=$(recsel -t MHD_Option -P Name -e "Value=$N" d_options.rec)
    COMMENT=$(recsel -t MHD_Option -P Comment -e "Value=$N" d_options.rec)
    ARGS=( )
    DESCRS=( )
    MEMBRS=( )
    [[ -n $NAME ]] || exit 2
    M=1
    while
        ARGM=$(recsel -t MHD_Option -P Argument${M} -e "Value=$N" d_options.rec)
        [[ -n $ARGM ]]
    do
        ARGS+=( "$ARGM" )
        DESCRM=$(recsel -t MHD_Option -P Description${M} -e "Value=$N" d_options.rec)
        if [[ -z $DESCRM ]]; then
            echo "Empty Description${M} for argument \"$ARGM\" for $NAME" >&2
            exit 2
        fi
        DESCRS+=( "$DESCRM" )
        MEMBRM=$(recsel -t MHD_Option -P Member${M} -e "Value=$N" d_options.rec)
        [[ -z $MEMBRM ]] && MEMBRM="$ARGM"
        MEMBRS+=( "$MEMBRM" )
        (( M++ ))
    done
    CBODY=""
    MBODY=""
    SBODY=""
    echo $N - $NAME
done

# recfmt -f d_option1.template tmp.rec
# recfmt -f d_option2.template tmp.rec
