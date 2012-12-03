import subprocess
from StringIO import StringIO
import cgi

class EndOfFile(Exception):
    pass


class Entry(object):

    _started = False
    _count = 0

    def __init__(self, name, account, password):
        self.name = name
        self.account = account
        self.password = password

    @staticmethod
    def roll(fi):
        """
        roll to next record
        """
        while True:
            Entry._count += 1
            line = fi.readline().strip()
            if line == '' and fi.tell() == fi.len:
                raise EndOfFile()
            if line.startswith('keychain: "'):
                break

    @staticmethod
    def parse(fi):
        if not Entry._started:
            Entry._started = True
            Entry.roll(fi)
        Entry._count += 1
        rtype = fi.readline().strip()
        if rtype not in ('class: "inet"', 'class: "genp"'):
            Entry.roll(fi)
            return Entry.parse(fi) # try next
        lines = []
        while True:
            Entry._count += 1
            line = fi.readline().strip()
            if line.startswith('keychain: "'):
                break
            lines.append(line)
        return lines

    @staticmethod
    def create(fi):
        lines = Entry.parse(fi)
        name = account = password = ''
        nextpassword = False
        for line in lines:
            if line.startswith('"srvr"<blob>="') or line.startswith('"svce"<blob>="'):
                name = line.replace('"srvr"<blob>="', '').replace(
                    '"svce"<blob>="', '').strip('"')
            elif line.startswith('"acct"<blob>="'):
                account = line.replace('"acct"<blob>="', '').strip('"')
            elif line.startswith('data:'):
                nextpassword = True
            elif nextpassword:
                password = line[1:-1]
        return Entry(name, account, password)


if __name__ == '__main__':
    # security dump-keychain -d login.keychain
    call = subprocess.Popen([
        'security',
        'dump-keychain',
        '-d',
        'login.keychain'
        ],
        stderr = subprocess.PIPE,
        stdout = subprocess.PIPE,
    )
    stdoutdata, stderrdata = call.communicate()
    entries = []
    data = StringIO(stdoutdata)
    while True:
        try:
            entries.append(Entry.create(data))
        except EndOfFile:
            break
    fi = open('output.xml', 'w')
    fi.write("""<!DOCTYPE KEEPASSX_DATABASE>
<database>
 <group>
  <title>Imported</title>
  <icon>1</icon>
""")

    for entry in entries:
        fi.write("""<entry>
   <title>%s</title>
   <username>%s</username>
   <password>%s</password>
   <url></url>
   <comment></comment>
   <icon>1</icon>
   <creation>2012-12-02T01:30:20</creation>
   <lastaccess>2012-12-02T01:30:39</lastaccess>
   <lastmod>2012-12-02T01:30:39</lastmod>
   <expire>Never</expire>
  </entry>
""" % (cgi.escape(entry.name), cgi.escape(entry.account), cgi.escape(entry.password)))

    fi.write("""</group></database>""")
    fi.close()
