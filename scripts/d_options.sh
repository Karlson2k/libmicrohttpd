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

if [[ $'\n' = '
' ]] ; then : ; else
  echo "Error: ANSI-C quoting support is required" >&2
  exit 1
fi

if [[ "abc" =~ 'b' ]] && [[ "xyz" =~ [x-z]{3} ]] ; then : ; else
  echo "Error: Regular expression match support is required" >&2
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

# fixed strings
flat_arg_descr='the value of the parameter'

err_exit() {
    local msg="$1"
    local err=$2
    
    [[ -z $msg ]] && msg="Error!"
    ( [[ -z $err ]] || (( err < 1 )) ) && err=2
    echo "$msg" >&1
    exit $err
}

# cut string an newline character
cut_str_nl() {
    local str="$1"
    declare -g cut_str_nl_res=''
    if [[ "$str" =~ $'\n' ]]; then
        cut_str_nl_res="${str%%$'\n'*}"
        return 0
    fi
    return 1
}

# cut string to given length at word boundary if possible
# process embedded new line characters
cut_str_word () {
    local str="$1"
    local len=$2
    declare -g cut_str_word_res=''
    [[ $len -le 0 ]] && return 1
    if cut_str_nl "${str:0:$(( len + 1 ))}"; then
        cut_str_word_res="${cut_str_nl_res}"
        return 0
    fi
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

format_doxy() {
    local prefix1="$1" # first line prefix
    local desc="$2"
    local prefix2="$3" # prefix on all other lines
    local width="$4"
    local tmp_str
    declare -g format_doxy_res=''
    [[ -z $width ]] && width=$max_width
    prefix1="${prefix1%"${prefix1##*[! ]}"} " # force single trailing space
    [[ -z $prefix2 ]] && prefix2="$prefix1"
    [[ ${#prefix1} -ge $width ]] && err_exit "Too long prefix ('${prefix1}') for width $width."
    desc="${desc#"${desc%%[! ]*}"}"
    desc="${desc%"${desc##*[! ]}"}" # trim desc
    local width_r=$(( width - ${#prefix1} ))
    local tmp_str="${prefix1//?/ }" # Space-only string with the same length
    prefix2="
${prefix2}${tmp_str:${#prefix2}}"
    cut_str_word "$desc" $width_r || return 1
    format_doxy_res="${prefix1}${cut_str_word_res}"
    desc="${desc:${#cut_str_word_res}}"
    desc="${desc#"${desc%%[! ]*}"}" # trim leading spaces
    desc="${desc#$'\n'}" # remove leading newline character
    while [[ -n "$desc" ]]; do
        cut_str_word "$desc" $width_r || return 1
        format_doxy_res+="${prefix2}${cut_str_word_res}"
        desc="${desc:${#cut_str_word_res}}"
        desc="${desc#"${desc%%[! ]*}"}" # trim leading spaces
        desc="${desc#$'\n'}" # remove leading newline character
    done
    return 0
}

def_name_for_type() {
    case $1 in
        'enum MHD_Bool') echo -n "bool_val";;
        'unsigned int') echo -n "uint_val";;
        'uint_fast64_t') echo -n "uint64_val";;
        'uint_fast32_t') echo -n "uint32_val";;
        'uint_fast16_t') echo -n "uint16_val";;
        'size_t') echo -n "sizet_val";;
        *) printf '%s' "${1// /_}_val"
    esac
}


cat << _EOF_ > "$tmp_rec"
%rec: MHD_Option_preproc
%mandatory: Value
%mandatory: Name
%type: Value int
%sort: Value

_EOF_

echo "Processing input file..."
for N in $(recsel -t MHD_Option -R Value "$input_rec")
do
    NAME=$(recsel -t MHD_Option -P Name -e "Value=$N" "$input_rec")
    if [[ -z $NAME ]]; then
      echo "The 'Name' field is empty for 'Value=$N'" >&2
      exit 2
    fi
    echo "$N: ${NAME^^}"
    COMMENT=$(recsel -t MHD_Option -P Comment -e "Value=$N" "$input_rec")
    if [[ -z $COMMENT ]]; then
      echo "The 'Comment' field is empty for '$NAME' ('Value=$N')" >&2
      exit 2
    fi
    TYPE=$(recsel -t MHD_Option -P Type -e "Value=$N" "$input_rec")
    EComment="" # The initial part of doxy comment for the enum value
    EName=""    # The final part of the name of the enum value
    UName=""    # The final part of the name of the union member
    UType=""    # The type of the union member
    SComment="" # The doxy comment for the set macro/function
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
    
    format_doxy '   * ' "$COMMENT" || err_exit
    EComment="$format_doxy_res"
    
    format_doxy ' * ' "$COMMENT" || err_exit
    SComment="$format_doxy_res"
    
    # Read option parameters
    ARGS=( )
    DESCRS=( )
    MEMBERS=( )
    M=1
    while
        ARGM=$(recsel -t MHD_Option -P Argument${M} -e "Value=$N" "$input_rec")
        [[ -n $ARGM ]]
    do
        ARGS[$M]="$ARGM"
        DESCRS[$M]="$(recsel -t MHD_Option -P Description${M} -e "Value=$N" "$input_rec")"
        MEMBERS[$M]="$(recsel -t MHD_Option -P Member${M} -e "Value=$N" "$input_rec")"
        (( M++ ))
    done
    
    # Basic data checks
    (( M - 1 == ${#ARGS[@]} )) || err_exit
    
    if [[ ${#ARGS[@]} -eq 0 ]]; then
        [[ -z $TYPE ]] && err_exit "No 'Argument1' is specified for '$NAME' ('Value=$N') without 'Type'" >&2
        nested='no'
        ARGS[1]=''
        DESCRS[1]="$flat_arg_descr"
        MEMBERS[1]=''
    elif [[ ${#ARGS[@]} -eq 1 ]]; then
        nested='no'
    else
        nested='yes'
        [[ -z $TYPE ]] && err_exit "No 'Type' is specified for non-flat (nested, with multiple parameters) '$NAME' ('Value=$N')" >&2
    fi
    
    # Process option parameters
    for (( M=1 ; M <= ${#ARGS[@]} ; M++ )) ; do
        
        arg_name='' # The name of the current argument
        arg_type='' # The type of the data of the current argument
        arg_descr='' # The description of the current argument
        nest_member='' # The name of the member of the nested structure
        # Pre-process parameters data
        if [[ -n ${ARGS[$M]} ]]; then
            arg_name="${ARGS[$M]##* }"
            arg_name="${arg_name#\*}"
            arg_type="${ARGS[$M]%${arg_name}}"
            arg_type="${arg_type% }"
        else
            if [[ $nested = 'yes' ]]; then
                err_exit "Empty or no 'Argument${M}' ('$arg_type') for '$NAME' ('Value=$N')"
            else
                [[ -z $TYPE ]] && err_exit "No 'Argument1' is specified for '$NAME' ('Value=$N') without 'Type'" >&2
                arg_name="$(def_name_for_type "$TYPE")"
                arg_type="$TYPE"
            fi
        fi
        arg_descr="${DESCRS[$M]}"
        nest_membr="${MEMBERS[$M]}"

        [[ -z $arg_name ]] && err_exit # Should not happen
        if [[ $nested = 'yes' ]]; then
            # non-flat, nested
            [[ -z $arg_type ]] && err_exit "No argument type in 'Argument${M}' ('${ARGS[$M]}') for $NAME ('Value=$N')"
            [[ $TYPE = $arg_type ]] && \
                err_exit "The same 'Type' and type for in 'Argument${M}' ('$arg_type') used for non-flat (nested) '$NAME' ('Value=$N')"
            [[ -z $arg_descr ]] && \
                err_exit "Empty or no 'Description${M}' for argument '${ARGS[$M]}' for '$NAME' ('Value=$N')"
            [[ -z $nest_membr ]] && \
                err_exit "Empty or no 'Member${M}' for argument '${ARGS[$M]}' for nested (non-flat) '$NAME' ('Value=$N')"
        else
            # flat, non-nested
            if [[ -z $arg_type ]]; then
                if [[ -z $TYPE ]]; then
                    err_exit "Both 'Type' and type for in 'Argument${M}' ('${ARGS[$M]}') are empty for '$NAME' ('Value=$N')"
                else
                    arg_type="$TYPE"
                fi
            else
                if [[ -z $TYPE ]]; then
                    TYPE="$arg_type"
                elif [[ $TYPE != $arg_type ]]; then
                    err_exit "Different 'Type' ('$TYPE') and type for in 'Argument${M}' ('$arg_type') used for '$NAME' ('Value=$N')"
                fi
            fi
            [[ -z $arg_descr ]] && arg_descr="$flat_arg_descr"
            [[ -n $nest_membr ]] && \
                err_exit "'Member${M}' is provided for non-nested (flat) '$NAME' ('Value=$N')"
        fi
        
        [[ "$arg_type" =~ \*$ ]] || arg_type+=' ' # Position '*' correctly
        
        [[ $M -gt 1 ]] && [[ $nested = 'no' ]] && err_exit
        
        # Use parameters data
        
        format_doxy ' * @param '"$arg_name " "$arg_descr" ' * '|| err_exit
        SComment+=$'\n'"$format_doxy_res"
        
        [[ $M -gt 1 ]] && MArguments+=','
        MArguments+="$arg_name"
        
        if [[ $nested = 'yes' ]]; then
            [[ $M -gt 1 ]] && SFArguments+=','
            SFArguments+=$'\n'"  ${arg_type}$arg_name"
        else
            SFArguments+="${arg_type}$arg_name"
        fi
        
        #[[ $M -gt 1 ]] && CLBody+=', \'$'\n'"    "
        [[ $M -gt 1 ]] && CLBody+=', \##removeme##'$'\n'"    " # '##removeme##' is a workaround for requtils bug
        CLBody+=".val.v_${UName}"
        [[ $nested = 'yes' ]] && CLBody+=".${nest_membr}"
        CLBody+=" = ($arg_name)"

        [[ $M -gt 1 ]] && SFBody+=$'\n'"  "
        SFBody+="opt.val.v_${UName}"
        [[ $nested = 'yes' ]] && SFBody+=".${nest_membr}"
        SFBody+=" = ${arg_name};"
        
    done
    UType="$TYPE"
    
    recins -t MHD_Option_preproc \
        -f Name -v "$NAME" \
        -f Value -v "$N" \
        -f EComment -v "$EComment" \
        -f EName -v "$EName" \
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
recfmt -f d_options_macro.template <"$tmp_rec" | ${SED-sed} -e 's/##removeme##//g' - > macro_insert.h
recfmt -f d_options_func.template <"$tmp_rec" > func_insert.h
# rm "$tmp_rec"
echo "finished."
