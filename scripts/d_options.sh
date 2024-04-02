#!/bin/bash

#   This file is part of GNU libmicrohttpd
#   Copyright (C) 2024 Karlson2k (Evgeny Grin), Christian Grothoff

#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.

#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.

#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA  02110-1301  USA


export LC_ALL=C
export LANG=C

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

if [[ "false" ]] ; then : ; else
  echo "Error: Compound command support is required" >&2
  exit 1
fi

test_var="abc ABC Abc"
if test "${test_var^}" = "Abc ABC Abc" && test "${test_var^^}" = "ABC ABC ABC" && test "${test_var,,}" = "abc abc abc"; then : ; else
  echo "Error: Shell upper- and lowercase variable conversion support required" >&2
  exit 1
fi

if test "${test_var// /_}" = "abc_ABC_Abc" ; then : ; else
  echo "Error: Shell variable replacement conversion support required" >&2
  exit 1
fi

unset test_var

# parameters
max_width=79
input_rec="d_options.rec"
tmp_rec="d_options_preproc.rec"

err_exit() {
    local msg="$1"
    local err=$2
    
    [[ -z $msg ]] && msg="Error!"
    ( [[ -z $err ]] || (( err < 1 )) ) && err=2
    echo "$msg" >&1
    exit $err
}
  
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
    prefix1="${prefix1%"${prefix1##*[! ]}"} " # force single trailing space
    [[ -z $prefix2 ]] && prefix2="$prefix1"
    desc="${desc#"${desc%%[! ]*}"}"
    desc="${desc%"${desc##*[! ]}"}" # trim desc
    local width_r=$(( width - ${#prefix1} ))
    local tmp_str="${prefix1//?/ }" # Space-only string with the same length
    prefix2="
${prefix2}${tmp_str:${#prefix2}}"
    cut_str_word "$desc" $width_r || return 1
    format_param_descr_res="${prefix1}${cut_str_word_res}"
    desc="${desc:${#cut_str_word_res}}"
    desc="${desc#"${desc%%[! ]*}"}" # trim leading spaces
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
    if [[ -z $NAME ]]; then
      echo "The 'Name' field is empty for 'Value=$N'" >&2
      exit 2
    fi
    echo $N: $NAME
    COMMENT=$(recsel -t MHD_Option -P Comment -e "Value=$N" "$input_rec")
    if [[ -z $COMMENT ]]; then
      echo "The 'Comment' field is empty for '$NAME' ('Value=$N')" >&2
      exit 2
    fi
    TYPE=$(recsel -t MHD_Option -P Type -e "Value=$N" "$input_rec")
    EComment="" # The doxy comment for enum value
    EName=""    # The final part of the name of the enum value
    UComment="" # The doxy comment for the union member
    UName=""    # The final part of the name of the union member
    UType=""    # The type of the union member
    SComment="" # The doxy comment for the value set macro and set function
    SName=""    # The final part of the name of the set macro/function
    MArguments=""   # The arguments for the macro
    CLBody=""   # The Compound Literal body (for the set macro)
    SFArguments=""  # The arguments for the static function
    SFBody=""   # The static function body
    
    nested='maybe'  # The option has nested struct parameters ('yes'/'no'/'maybe')

    clean_name="${NAME//_/ }"
    clean_name="${clean_name,,}" # Lowercase space-delimited

    EName="${clean_name^^}"
    EName="${EName// /_}" # Uppercase '_'-joined
    
    UName="${clean_name// /_}" # lowercase '_'-joined
    
    SName="${EName}" # Uppercase '_'-joined

    [[ -z $TYPE ]] && nested='no'
    
    arg_names=( )
    arg_types=( )
    arg_descr=( )
    nest_membr=( )
    M=1
    while
        ARGM=$(recsel -t MHD_Option -P Argument${M} -e "Value=$N" "$input_rec")
        [[ -n $ARGM ]]
    do
        DESCRM=$(recsel -t MHD_Option -P Description${M} -e "Value=$N" "$input_rec")
        if [[ -z $DESCRM ]]; then
            echo "Empty Description${M} for argument \"$ARGM\" for '$NAME' ('Value=$N')" >&2
            exit 2
        fi
        MEMBRM=$(recsel -t MHD_Option -P Member${M} -e "Value=$N" "$input_rec")
        
        arg_name="${ARGM##* }"
        arg_name="${arg_name#\*}"
        arg_type="${ARGM%${arg_name}}"
        arg_type="${arg_type% }"
        
        if [[ -z $arg_type ]]; then
            if [[ $M -eq 1 ]]; then
                if [[ -z $TYPE ]]; then
                    echo "No argument type for $NAME ('Value=$N')" >&2
                    exit 2
                else
                    arg_type="$TYPE"
                    nested='no'
                fi
            else
                echo "No argument type found in 'Argument${M}' (\"$ARGM\") for '$NAME' ('Value=$N')" >&2
                exit 2
            fi
        else
            if [[ -z $TYPE ]]; then
                if [[ $M -eq 1 ]]; then
                    TYPE="$arg_type"
                    nested='no'
                else
                    echo "Empty 'Type' for '$NAME' ('Value=$N') with multiple parameters" >&2
                    exit 2
                fi
            else
                if [[ $TYPE = $arg_type ]]; then
                    if [[ $M -eq 1 ]]; then
                        nested='no'
                    else
                        echo "The same 'Type' and type for in 'Argument${M}' (\"$ARGM\") used for '$NAME' ('Value=$N')" >&2
                        exit 2
                    fi
                else
                    nested='yes'
                fi
            fi
        fi
        [[ $nested = 'maybe' ]] && err_exit "Internal error"
        if [[ $M -gt 1 ]]; then
            if [[ $nested = 'no' ]]; then
                echo "The 'Argument${M}' (\"$ARGM\") is specified for flat (non-nested) '$NAME' ('Value=$N')" >&2
                exit 2
            elif [[ $nested = 'maybe' ]]; then
                nested='yes'
            fi
        fi
        (( M++ ))
    done
    if (( M < 2 )); then
        [[ -z $TYPE ]] && err_exit "No 'Argument1' is specified for '$NAME' ('Value=$N') without 'Type'" >&2
        [[ $nested = 'yes' ]]  && err_exit "No 'Argument1' is specified for non-flat (nested) '$NAME' ('Value=$N')" >&2
    fi
    UType="$TYPE"
    
    recins -t MHD_Option_preproc \
        -f Name -v "$NAME" \
        -f Value -v "$N" \
        -f EComment -v "$EComment" \
        -f EName -v "$EName" \
        -f UComment -v "$UComment" \
        -f UName -v "$UName" \
        -f UType -v "$UType" \
        -f SComment -v "$SComment" \
        -f SName -v "$SName" \
        -f MArguments -v "$MArguments" \
        -f CLBody -v "$CLBody" \
        -f SFArguments -v "$SFArguments" \
        -f SFBody -v "$SFBody" \
        "$tmp_rec"
done
echo "finished."

echo "Generating output files..."
recfmt -f d_options_enum.template <"$tmp_rec" > enum_insert.h
recfmt -f d_options_union.template <"$tmp_rec" > union_insert.h
recfmt -f d_options_macro.template <"$tmp_rec" > macro_insert.h
recfmt -f d_options_func.template <"$tmp_rec" > func_insert.h
# rm "$tmp_rec"
echo "finished."
