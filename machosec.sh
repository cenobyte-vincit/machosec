#!/bin/bash
#
# machosec.sh by cenobyte <vincitamorpatriae@gmail.com> 2020
#
# Checks the security of Mach-O 64-bit executables and application bundles
#
# It is able to identify:
# - dyld injection vulnerabilities
# - LC_RPATH vulnerabilities leading to dyld injection
# - symlinks pointing to attacker controlled locations
# - writable by others vulnerabilities
# - missing stack canaries
# - disabled PIE (ASLR)
# - disabled FORTIFY_SOURCE (keeping insecure functions such as strcpy, memcpy etc.)
#
# And it shows (targets of interest):
# - setuid and setgid executables
# - files and directories writable by others
# - linking to non-existent dyld's (which potentially leads to dyld injection)
#
# Example (on the readelf binary from Brew):
# $ sudo ./machosec.sh /usr/local/bin/greadelf
# '/usr/local/bin/greadelf'
# ├── not code signed
# └── PIE (ASLR) disabled
#
# Written and tested on macOS 10.15.7
#
# Tip: ls /Applications | while read x; do sudo ./machosec.sh "/Applications/${x}"; done

readonly __progname="${BASH_SOURCE[0]}"
readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"

export output=""

usage() {
	echo -e "usage: ${__progname} <Mach-O executable / Application bundle>" >&2

	exit 1
}

errx() {
	echo -e "${__progname}: $*" >&2

	exit 1
}

addoutput() {
	[ -z "$1" ] && \
		return

	local tmp="$1"

	[ -z "${output}" ] || \
		tmp="$(echo -e "${output}\n$1")"

	output="${tmp}"
	tmp=""
}

perms() {
	if [ ! -e "$1" ]; then
		addoutput "does not exist: '$1'"
		return
	fi

	# L(ow)
	stat -f "%SLp" "$1" | grep -q "w" && \
		addoutput "'$1': W_OTH flag set"

	# M(ed)
	stat -f "%SMp" "$1" | grep -q "s" && \
		addoutput "'$1': S_ISGID flag set"

	# H(igh)
	stat -f "%SHp" "$1" | grep -q "s" && \
		addoutput "'$1': S_ISUID flag set"
}

listdylibs() {
	otool -L "$1" 2>/dev/null | \
		grep '\t' | \
		tr -d '\t' | \
		cut -d '(' -f 1 | \
		grep '^/' | \
		sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/[[:space:]]/,/'
}

listnonsysdylibs() {
	local SAVEIFS="${IFS}"
	local IFS="$(echo -en "\n\b")"

	for dylib in $(listdylibs "$1" | egrep -v "^/System/|^/usr/lib/|^/Library/|^/Applications/"); do
		[ -z "${dylib}" ] && \
			continue

		addoutput "linked to a non-system dylib: '${dylib}' (potentially attacker controlled)"

		# dyld's can also be linked, so check whether there is something wrong with those sub-dyld's
		# but just exclude the ones in /Applications
		for subdylib in $(listdylibs "${dylib}" | egrep -v "^/System/|^/usr/lib/|^/Library/|^/Applications/" | grep -vw "${dylib}"); do
			[ -z "${subdylib}" ] && \
				continue

			addoutput "'${dylib}' is linked to a non-system dylib: '${subdylib}' (potentially attacker controlled)"
			perms "${subdylib}"
		done
	done

	local IFS="${SAVEIFS}"
}

vulndylibs() {
	local SAVEIFS="${IFS}"
	local IFS="$(echo -en "\n\b")"

	for dylib in $(listdylibs "$1"); do
		perms "${dylib}"
	done

	local IFS="${SAVEIFS}"
}

canarycheck() {
	otool -Iv "$1" 2>/dev/null | \
		grep -q "__stack_chk" || \
			addoutput "no stack canary (missing '__stack_chk')"
}

codesigned() {
	codesign -vvvv "$1" 2>&1 | \
		grep -q "code object is not signed at all" && \
			addoutput "not code signed"
}

pie() {
	otool -hv "$1" 2>/dev/null | grep -qw PIE || \
		addoutput "PIE (ASLR) disabled"
}

rpath() {
	# check for rpath dyld
	otool -L "$1" | grep -q '@rpath' || \
		return

	SAVEIFS="${IFS}"
	IFS="$(echo -en "\n\b")"

	# check for executable_path which could be exploited by creating a hard link
	# only useful when the target is setuid root
	rpathexec="0"

	stat -f "%Sp" "$1" | grep -q "s"
	if [ $? -eq 0 ]; then
		for execpath in $(otool -l "$1" | \
			grep -A2 LC_RPATH | \
			grep 'path @executable_path/' | \
			cut -d '@' -f 2 | \
			cut -d '(' -f 1 | \
			sed 's@executable_path/@@' | \
			sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/[[:space:]]/,/' | \
			sort -u); do
				addoutput "LC_RPATH points to '@executable_path' (potentially attacker controlled): '${execpath}'"
				rpathexec="1"
		done
	fi

	# check for absolute path (but filter /usr/lib/ etc.)
	for absolutepath in $(otool -l "$1" | \
		grep -A2 LC_RPATH | \
		grep 'path /' | \
		cut -d '(' -f 1 | \
		sed 's@path /@/@' | \
		tr -d '^ ' | \
		sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/[[:space:]]/,/' | \
		egrep -v "^/System/|^/usr/lib/|^/Library/|^/Applications/"); do
			addoutput "LC_RPATH points to an absolute path (potentially attacker controlled): '${absolutepath}'"
			perms "${absolutepath}"
			rpathexec="1"
	done

	if [ "${rpathexec}" -eq 1 ]; then
		for rpathdir in $(otool -L "$1" | \
			grep '@rpath' | \
			cut -d '@' -f 2 | \
			cut -d '(' -f 1 | \
			sed 's@^rpath/@@' | \
			sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/[[:space:]]/,/'); do
				addoutput "injectable dyld: '<executable path | absolute path>/${rpathdir}'"
		done
	fi

	IFS="${SAVEIFS}"
}

symlinks() {
	local symlink="$1"
	local symlinksource="$(stat -l "${symlink}" | cut -d '>' -f 2 | tr -d '^ ')"
	local underlyingdir="$(dirname "${symlink}")"

	# build absolute path in case relative path was used
	echo "${symlinksource}" | grep -q '^/'
	if [ $? -ne 0 ]; then
		# insert full path if the dirname is '.'
		[[ "${underlyingdir}" == "." ]] && \
			underlyingdir="$(dirname "${symlink}")"

		symlinksource="$(echo "${underlyingdir}/${symlinksource}" | sed 's@/\./@/@')"
	else
		echo "${symlinksource}" | grep -q '^./' && \
			symlinksource="$(echo "${symlinksource}" | sed 's@/\./@/@')"
	fi

	# only show symlinks from sources outside /Applications and system locations as these might be attacker controlled
	echo "${symlinksource}" | \
		egrep -v "^/System/|^/usr/lib/|^/Library/|^/Applications/" | \
		egrep -qi "[a-z]" || \
			return

	addoutput "'${symlink}' -> '${symlinksource}' (potentially attacker controlled)"
	perms "${symlinksource}"
}

fortifysource() {
	# With FORTIFY_SOURCE, GCC uses replacement functions for strcpy(), memcpy(), etc.
	otool -Iv "$1" 2>/dev/null | grep -v stack | grep -q _chk && \
		return

	# so we now know that the binary does not have _chk replacement functions
	# and now we need to check whether it uses any insecure functions
	# if any insecure functions are found then we know that FORTIFY_SOURCE was disabled
	useinsecure="0"
	for insecure in "memcpy" "mempcpy" "memmove" "memset" \
		"strcpy" "stpcpy" "strncpy" "strcat" \
		"strncat" "sprintf" "vsprintf" "snprintf" \
		"vsnprintf" "gets"; do
			otool -Iv "$1" 2>/dev/null | grep -qw "${insecure}"
			if [ $? -eq 0 ]; then
				readonly useinsecure="1"
				break
			fi
	done

	[ "${useinsecure}" -eq 1 ] && \
		addoutput "uses insecure functions such as ${insecure}() - it appears that FORTIFY_SOURCE was disabled"
}

checkmacho() {
	export output=""
	addoutput "'$1'"

	codesigned "$1"
	canarycheck "$1"
	pie "$1"
	fortifysource "$1"
	perms "$1"
	listnonsysdylibs "$1"
	vulndylibs "$1"
	rpath "$1"

	print

	return 0
}

checkappbundle() {
	perms "$1"

	SAVEIFS="${IFS}"
	IFS="$(echo -en "\n\b")"

	export output=""
	addoutput "'$1'"
	for wothent in $(find "$1" -perm -o+w 2>/dev/null); do
		addoutput "'${wothent}' W_OTH flag set"
	done
	print

	for appent in $(find "$1"); do
		file "${appent}" 2>/dev/null | grep -qw "Mach-O 64-bit executable" && \
			checkmacho "${appent}"
	done

	for symlink in $(find "$1"); do
		# check if symlink
		[ ! -h "${symlink}" ] && \
			continue

		export output=""
		symlinks "${symlink}"
		print
	done

	IFS="${SAVEIFS}"

	return 0
}

print() {
	# nothing to print
	[ -z "${output}" ] && \
		return

	len="$(echo "${output}" | wc -l | tr -d ' ')"
	[[ "${len}" -eq 1 ]] && \
		return

	# ready for JSON output mode
	i=1
	echo "${output}" | while read line; do
		if [ "${i}" == 1 ]; then
			# start
			echo "${line}"
		elif [ "${i}" == "${len}" ]; then
			# finish
			echo -e "└── ${line}\n"
		else
			echo "├── ${line}"
		fi

		((i++))
	done

	export output=""
}

main() {
	# sorry need root to check setuids in /usr/bin/ and /usr/sbin/
	[ "${EUID}" -ne 0 ] && \
		errx "need root"

	[[ "$#" -ne 1 ]] && \
		usage

	for bin in codesign otool file; do
		command -v "${bin}" >/dev/null 2>&1 || \
			errx "cannot find '${bin}' in 'PATH=${PATH}'"
	done

	# remove trailing slash
	local ent="${1%/}"
	[ ! -e "${ent}" ] && \
		errx "cannot open '${ent}'"

	if [ -f "${ent}" ]; then
		readonly ent
		file "${ent}" 2>/dev/null | grep -qw "Mach-O 64-bit executable"
		[ $? -ne 0 ] && \
			errx "'${ent}' is not a Mach-O 64-bit executable"

		checkmacho "${ent}"
	elif [ -d "${ent}" ]; then
		if [ ! -d "${ent}/Contents/MacOS" ]; then
			# Some Adobe products have a nested .app directory
			local tmp="$(ls "${ent}/" | grep '\.app' | head -1)"
			[ -z "${tmp}" ] && \
				errx "'${ent}' is not an application bundle"

			readonly ent="${ent}/${tmp}"
		fi

		checkappbundle "${ent}"
	fi

	return 0
}

main "$@"
