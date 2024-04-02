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
input_rec="d_options.rec"
tmp_rec="d_options_preproc.rec"
  
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
    local width="$4"
    local prefix2="$3" # prefix on all other lines
    local tmp_str
    declare -g format_param_descr_res=''
    [[ -z $width ]] && width=$max_width
    prefix1="${prefix1%${prefix1##*[! ]}} " # force single trailing space
    [[ -z $prefix2 ]] && prefix2="$prefix1"
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

cat << _EOF_ > "$tmp_rec"
%rec: MHD_Option_preproc
%mandatory: Value
%mandatory: Name
%type: Value int

_EOF_

echo "Processing input file..."
for N in $(recsel -t MHD_Option -R Value "$input_rec")
do
    NAME=$(recsel -t MHD_Option -P Name -e "Value=$N" "$input_rec")
    COMMENT=$(recsel -t MHD_Option -P Comment -e "Value=$N" "$input_rec")
    ARGS=( )
    DESCRS=( )
    MEMBRS=( )
    if [[ -z $NAME ]]; then
      echo "The name field is empty for 'Value=$N'" >&2
      exit 2
    fi
    EComment=""
    EName=""
    FComment=""
    MArguments=""
    CLBody=""
    SFArguments=""
    SFBody=""
    M=1
    while
        ARGM=$(recsel -t MHD_Option -P Argument${M} -e "Value=$N" "$input_rec")
        [[ -n $ARGM ]]
    do
        ARGS+=( "$ARGM" )
        DESCRM=$(recsel -t MHD_Option -P Description${M} -e "Value=$N" "$input_rec")
        if [[ -z $DESCRM ]]; then
            echo "Empty Description${M} for argument \"$ARGM\" for $NAME" >&2
            exit 2
        fi
        DESCRS+=( "$DESCRM" )
        MEMBRM=$(recsel -t MHD_Option -P Member${M} -e "Value=$N" "$input_rec")
        [[ -z $MEMBRM ]] && MEMBRM="$ARGM"
        MEMBRS+=( "$MEMBRM" )
        arg_name="${ARGM##* }"
        arg_name="${arg_name#\*}"
        arg_type="${ARGM%${arg_name}}"
        arg_type="${arg_type% }"
        (( M++ ))
    done
    echo $N - $NAME
    recins -t MHD_Option_preproc \
        -f Value -v "$N" \
        -f Name -v "$NAME" \
        -f EComment -v "$EComment" \
        -f EName -v "$EName" \
        -f MArguments -v "$MArguments" \
        -f CLBody -v "$CLBody" \
        -f SFArguments -v "$SFArguments" \
        -f SFBody -v "$SFBody" \
        "$tmp_rec"
done
echo "finished."

echo "Generating output files..."
# recfmt -f d_option0.template "$tmp_rec"
# recfmt -f d_option1.template "$tmp_rec"
# recfmt -f d_option2.template "$tmp_rec"
# rm "$tmp_rec"
echo "finished."
