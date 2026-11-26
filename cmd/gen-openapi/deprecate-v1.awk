# Marks every exported top-level declaration of the generated v1 client
# deprecated, as its own paragraph, so Go tools warn on each form of an
# operation. oapi-codegen v2.8.2 marks only some forms, and runs the mark into
# the paragraph before it on others. Run as: awk -f this file file
# (the file twice: the first pass reads the reason oapi-codegen wrote).

FNR == NR {
	if (reason == "" && match($0, /Deprecated: .*/)) {
		reason = substr($0, RSTART)
	}
	next
}

/^\/\// {
	block[n++] = $0
	next
}

{
	exported = $0 ~ /^(type|func) ([(][^)]*[)] )?[A-Z]/
	marked = 0
	for (i = 0; i < n; i++) {
		if (block[i] ~ /^\/\/ Deprecated:/) {
			if (i > 0 && block[i - 1] != "//") {
				print "//"
			}
			marked = 1
		}
		print block[i]
	}
	if (exported && !marked) {
		if (n > 0) {
			print "//"
		}
		print "// " reason
	}
	n = 0

	# Methods inside an interface: the same paragraph rule.
	if ($0 ~ /^[ \t]+\/\/ Deprecated:/ && prev ~ /^[ \t]+\/\/ /) {
		match($0, /^[ \t]*/)
		print substr($0, 1, RLENGTH) "//"
	}
	print
	prev = $0
}
