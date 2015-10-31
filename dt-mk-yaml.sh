#!/bin/bash

get_binding_files()
{
IFS='
'
	doc_files=$(git ls-files Documentation/devicetree/bindings/)

	for line in $*; do
		IFS=' '
		compat1=$(echo "$line" | cut -d' ' -f1)
		for compat in $line; do
			compat2=$(echo "$compat" | sed -e 's/.*\,//')
			# first search by filename
			binding_file=$(echo $doc_files | grep -E '\/('"$compat"'|'"$compat2"')($|\.txt)')
			if [ -n "$binding_file" ] && ! grep -q "$compat" "$binding_file"; then
				binding_file=""
			fi
			if [ -z "$binding_file" ]; then
				# next search for the doc with the most matches
				compat3=$(echo "$compat" | sed 's/\,[a-zA-Z0-9]*\-/\,<\.\*>\-/')
				compat4=$(echo "$compat" | sed 's/\,\([a-z]*\)[0-9]*\-/\,\1<\.\*>\-/')
				binding_file=$(git --no-pager grep -Ec '([\"[:space:]]|^)('"$compat"'|'"$compat3"'|'"$compat4"')([,\"[:space:]]|$)' HEAD -- Documentation/devicetree/bindings | sort -n -k2 -t: -r | head -1 | cut -d':' -f2 )
#				if [ -z "$binding_file" ]; then
#					echo "$compat" >> missing-compatibles.txt
#				fi
			fi
			if [ -n "$binding_file" ]; then
				echo "$compat1: $binding_file" >&2
				echo "$compat1: $binding_file"
				break
			fi
		done
	done
#	echo "No binding file for $*" >&2
}

rm -f missing-compatibles.txt

compats=$(perl -pe 'unless(eof){s/,\n/, /g}' arch/*/boot/dts/* | grep -P '^[ \t]*compatible.*=' | sed -e 's/.*=[ ]*\(.*\)\"\;.*/\1\"/g' -e 's/\"[\t ,]*\"/\" \"/g' | sort -u | tr -d \")
echo Found $(echo "$compats" | wc -l) compatible properties

echo $compats > compatible.txt

tmpfile=$(mktemp)
script_tmp=$(mktemp)


echo "Getting binding files..."
if [ -n "$1" ]; then
	binding_files=$(cat "$1")
else
	binding_files=$(get_binding_files "$compats")
	echo "$binding_files" > binding_files.txt
fi
echo "Done"

IFS='
'
for compat in $compats; do
	IFS=' '
	c=($compat)

	binding_file=$(echo "$binding_files" | grep "${c[0]]}" | cut -d' ' -f2 | head -1)
	if [ -z "$binding_file" ]; then
		continue;
	fi
	
	yaml_file=$(echo "$binding_file" | sed -e 's/\.txt\|\.yaml//' -e 's/$/.yaml/')
	if [ -f "$yaml_file" ]; then
                str=$(echo -n '           '; printf ' \"%s\"' "${c[@]}")
		perl -i -pe 'unless(eof){s/(constraint: \|\n)/$1'"$str"'\n/g}' $yaml_file
		continue
	fi
	echo "$yaml_file"

	# Move the file to a .yaml file and make all the doc a comment
	git mv $binding_file $yaml_file
	sed -i -e 's/^/# /' -e 's/[ \t]*$//' $yaml_file
	git add $yaml_file

        str=$(echo -n '           '; printf ' \"%s\"' "${c[@]}")
	printf "s/^.*%%compatible%%/%s/\n" "$str" > $script_tmp

	title=$(sed -e 's/^[^[:alnum:]]*//' -e '/^$/d' -e 's/\//\\\//g' -e "s/'/''/g" $yaml_file | head -1)
	printf 's/%%title%%/%s/\n' "$title" >> $script_tmp

	maintainer=$(git shortlog --no-merges -nse v3.0..HEAD -- $binding_file | head -1 | cut -c8-)
	printf "s/%%maintainer%%/%s/\n" "$maintainer" >> $script_tmp

	id=$(basename $yaml_file .yaml)
	printf "s/%%id%%/%s/\n" "$id" >> $script_tmp

	props=($(grep -e "^\"${c[0]}\"" dts-props.log | cut -d' ' -f2- -s | xargs -n1 | sort -u | xargs)) 
        str=""
#       for p in ${props[@]}; do
#        	type=$(echo "$p"| cut -d':' -f2 -s)
#        	case "$type" in
#        	S)
#        		type_str="string"
#        		;;
#        	E)
#        		type_str="empty"
#
#        		;;
#        	esac

#        	str=$(printf '%s    \"%s\"\:\\n        category\:\\n        constraint\:\\n        type\: %s\\n' "$str" "$p" "$type_Str")
#        done
       	str=$(printf '    \"%s\"\:\\n' ${props[@]})
	printf "s/%%props%%/%s/\n" "$str" >> $script_tmp

	inherits=($(grep -e "^\"${c[0]}\"" dts-inherits.log | cut -d' ' -f2- -s | xargs -n1 | sort -u | xargs))
        str=""
        if [ -n "${inherits[*]}" ]; then
        	str=$(printf '    - %s\\n' "${inherits[@]}")
        fi
	printf "s/%%inherits%%/%s/\n" "$str" >> $script_tmp

	# Create the yaml header
	#cat $script_tmp
	sed -f $script_tmp template.yaml > $tmpfile
	
	# Append the doc as comments
	cat $yaml_file >> $tmpfile
	mv $tmpfile $yaml_file
done

rm -f $tmpfile $script_tmp

