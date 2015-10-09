#!/bin/bash

find_binding_file()
{
	for c in $*; do
		compat=$1
		compat2=$(echo "$compat" | sed -e 's/.*\,//')
		# first search by filename
		binding_file=$(echo $doc_files | grep -E '\/('"$compat"'|'"$compat2"')($|.txt|.yaml)' )
		if [ -n "$binding_file" ] && ! grep -q "$compat" $(echo $binding_file | sed -e 's/\.txt//' -e 's/$/\*/'); then
			binding_file=""
		fi
		if [ -z "$binding_file"  ]; then
			# next search for the doc with the most matches
			compat3=$(echo "$compat" | sed 's/\,[a-zA-Z0-9]*\-/\,<\.\*>\-/')
			compat4=$(echo "$compat" | sed 's/\,\([a-z]*\)[0-9]*\-/\,\1<\.\*>\-/')
			binding_file=$(git --no-pager grep -Ec '([\"[:space:]]|^)('"$compat"'|'"$compat3"'|'"$compat4"')([,\"[:space:]]|$)' HEAD -- Documentation/devicetree/bindings | sort -n -k2 -t: -r | head -1 | cut -d':' -f2 )
			if [ -z "$binding_file" ]; then
				echo "$compat" >> missing-compatibles.txt
			fi
		fi
		if [ -n "$binding_file" ]; then
			echo -n "$binding_file"
			exit 0
		fi

		shift
	done
}

rm -f missing-compatibles.txt

compats=$(perl -pe 'unless(eof){s/,\n/, /g}' arch/*/boot/dts/* | grep -P '^[ \t]*compatible.*=' | sed -e 's/.*=\(.*\)\"\;.*/\1\"/g' -e 's/\"[\t ,]*\"/\" \"/g' | sort | uniq | tr -d \")
echo Found $(echo "$compats" | wc -l) compatible properties

echo $compats > compatible.txt

tmpfile=$(mktemp)

doc_files=$(git ls-files Documentation/devicetree/bindings/)

IFS='
'

for compat in $compats; do
	IFS=' '
	c=($compat)

	compat2=$(echo $compat | sed -e 's/\([a-zA-Z0-9\,\-]*\)/\"\1\"/g' -e 's/ / \\\&\\\& /g') 

	binding_file=$(find_binding_file ${c[*]})
	if [ -z "$binding_file" ]; then
		continue;
	fi
	echo $compat - $binding_file
	
	yaml_file=$(echo $binding_file | sed -e 's/\.txt\|\.yaml//' -e 's/$/.yaml/')
	if [ -f "$yaml_file" ]; then
		perl -i -pe 'unless(eof){s/(constraint.*\n)/$1            '"$compat2"'\n/g}' $yaml_file
		continue
	fi

	title=$(sed -e '/^$/d' -e 's/^\* //' -e 's/\//\\\//g' $binding_file | head -1)
	maintainer=$(git shortlog --no-merges -nse v3.0.. -- $binding_file | head -1 | cut -c8-)
	id=$(basename $yaml_file .yaml)

	props=$(grep -e "^\"${c[0]}\"" dts-props.log | cut -d' ' -f2-| sed -e 's/ /\n/g' | sort | uniq | perl -p -e 's/^/    /g' | perl -pe 's/\n/\\:\\n/g')
	#echo "$props"

	# Move the file to a .yaml file and make all the doc a comment
	git mv $binding_file $yaml_file
	sed -i -e 's/^/# /' -e 's/[ \t]*$//' $yaml_file
	git add $yaml_file

	# Create the yaml header
	sed -e 's/\%compatible\%/'"$compat2"'/' -e 's/\%maintainer\%/'"$maintainer"'/' \
	    -e 's/ \%title\%/ '"$title"'/' -e 's/\%id\%/'"$id"'/' -e 's/\%props\%/'"$props"'/' template.yaml > $tmpfile
	
	# Append the doc as comments
	cat $yaml_file >> $tmpfile
	mv $tmpfile $yaml_file
done

rm -f $tmpfile
