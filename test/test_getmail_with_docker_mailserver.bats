load 'test_helper/common'

source config/self_sign.sh
export PSS TESTEMAIL NAME

function setup() {
    setup_file
}

function teardown() {
    run_teardown_file_if_necessary
}

function setup_file() {
    source '.env'
    export HOSTNAME DOMAINNAME CONTAINER_NAME SELINUX_LABEL
    wait_for_finished_setup_in_container ${NAME}
    local STATUS=0
    repeat_until_success_or_timeout --fatal-test "container_is_running ${NAME}" "${TEST_TIMEOUT_IN_SECONDS}" sh -c "docker logs ${NAME} | grep 'is up and running'" || STATUS=1
    if [[ ${STATUS} -eq 1 ]]; then
        echo "Last ${NUMBER_OF_LOG_LINES} lines of container \`${NAME}\`'s log"
        docker logs "${NAME}" | tail -n "${NUMBER_OF_LOG_LINES}"
    fi
    return ${STATUS}
}

function teardown_file() {
    : # docker-compose down
}

@test "first" {
  skip 'this test must come first to reliably identify when to run setup_file'
}

@test "checking ssl" {
  run docker exec $NAME /bin/bash -c "\
    openssl s_client -connect 0.0.0.0:25 -starttls smtp -CApath /etc/ssl/certs/"
  assert_success
}

# pop   = 110
# imap  = 143
# imaps = 993
# pops  = 995
# smtp  = 25
# smtps = 587

testmail(){
  docker exec $NAME bash -c "nc 0.0.0.0 25 << EOF
HELO mail.localhost
MAIL FROM: ${TESTEMAIL}
RCPT TO: ${TESTEMAIL}
DATA
Subject: test
This is the test text:
я αβ один süße créme in Tromsœ.
.
QUIT
EOF
"
}

@test "IMAPS, destination Maildir, from host" {
testmail
PORTNR=993
KIND=IMAP
TMPMAIL=/tmp/Mail
MAILDIRIN=$TMPMAIL/$TESTEMAIL/INBOX
rm -rf $MAILDIR
mkdir -p $MAILDIRIN/{cur,tmp,new}
cat > /tmp/getmail <<EOF
[retriever]
type = Simple${KIND}SSLRetriever
server = localhost
username = $TESTEMAIL
port = $PORTNR
password = $PSS
[destination]
type = Maildir
path = $MAILDIRIN/
[options]
read_all = true
delete = true
EOF
getmail --rcfile=getmail --getmaildir=/tmp
[[ -n "$(find $MAILDIRIN/new -type f)" ]]
assert_success
}


@test "IMAPS, destination Maildir" {
testmail
PORTNR=993
KIND=IMAP
TMPMAIL=/home/getmail/Mail
MAILDIR=$TMPMAIL/$TESTEMAIL
MAILDIRIN=$MAILDIR/INBOX
run docker exec -u getmail $NAME bash -c "
rm -rf $MAILDIR && \
mkdir -p $MAILDIRIN/{cur,tmp,new} && \
cat > /home/getmail/getmail <<EOF
[retriever]
type = Simple${KIND}SSLRetriever
server = localhost
username = $TESTEMAIL
port = $PORTNR
password = $PSS
[destination]
type = Maildir
path = $MAILDIRIN/
[options]
read_all = true
delete = true
EOF"
assert_success
docker exec -u getmail $NAME bash -c " \
getmail --rcfile=getmail --getmaildir=/home/getmail"
assert_success
}

@test "IMAPS, destination procmail filter spamassassin clamav" {
testmail
PORTNR=993
KIND=IMAP
TMPMAIL=/home/getmail/Mail
MAILDIR=$TMPMAIL/$TESTEMAIL
MAILDIRIN=$MAILDIR/INBOX
run docker exec -u getmail $NAME bash -c " \
rm -rf $MAILDIR && \
mkdir -p $MAILDIRIN/{cur,tmp,new} && \
mkdir -p $MAILDIR/tests/{cur,tmp,new} && \
cat > /home/getmail/getmail <<EOF
[retriever]
type = Simple${KIND}SSLRetriever
server = localhost
username = $TESTEMAIL
port = $PORTNR
password = $PSS
[destination]
type = MDA_external
path = /usr/bin/procmail
arguments = ('-f', '%(sender)', '-m', '/home/getmail/procmail')
#pacman -S spamassassin
[filter-1]
type = Filter_external
path = /usr/bin/spamassassin
ignore_header_shrinkage = True
#pacman -S clamav
[filter-2]
type = Filter_classifier
path = /usr/bin/clamscan
arguments = ('--stdout', '--no-summary', '--scan-mail', '--infected', '-')
exitcodes_drop = (1,)
[options]
read_all = true
delete = true
EOF"
assert_success
run docker exec -u getmail $NAME bash -c " \
cat > /home/getmail/procmail <<EOF
MAILDIR=$MAILDIR
DEFAULT=\$MAILDIR/INBOX
:0
* ^Subject:.*test.*
tests/
:0
\$DEFAULT/
EOF"
assert_success
run docker exec -u getmail $NAME bash -c " \
getmail --rcfile=getmail --getmaildir=/home/getmail"
assert_success
}
