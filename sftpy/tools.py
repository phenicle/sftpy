# sftpy.py

# license placeholder here

"""
 What: The sftpy python module
  Why: Because we were forced to create ssftpy.
       And sftplib's API isn't consistent with ssftpy.
       This is an opportunity to use a single, consistent
       API across both sftp and ssftp under python.

 Open Questions: 

   Is there a way to tell which API elements are
   supported by the external FTP client pexpect is using?

 Future:

   Transition from dependence on pexpect to using
   native C FTP library calls.

"""
import sys
import os
import stat
from pwd import getpwuid
import pexpect
import re
import pprint
from distutils.spawn import find_executable
import errno
from cfgpy.tools import FMT_INI, CfgPy

DEBUGGING = False

# session debugging constants
# determines what, if anything
SESSDBGN = 0   # show nothing
SESSDBGR = 1   # show reads
SESSDBGW = 2   # show writes
SESSDBGRW = 3  # show reads and writes

# file transfer modes
MODE_BINARY = 1  # binary is default
MODE_TEXT = 2

# path type indicator constants
PATH_TYPE_UNKNOWN  = 0
PATH_TYPE_FILEPART = 1
PATH_TYPE_DIRPART  = 2
PATH_TYPE_COMPOUND = 3

STATE_UNKNOWN = 0
STATE_START = 1
STATE_LOGGED_IN = 2

pp = pprint.PrettyPrinter(indent=4)

class Sftp(object):
	""" 
	The Sftp class

    Argument list for the object ctor (__init__).
    We now support two different ways of initializing/configuring new objects.
    
    1. native (secure)

    Arguments:  <arg1> <arg2>

     where 
      <arg1> := host (string)
      <arg2> := user (string)

    2. cfgpy

    Arguments: <arg1> <arg2>

     where
      <arg1> := a CfgPy object
      <arg2> := a dictionary having this form:

       { 
        'host': <cfgpy-keypath-tuple>,
        'user': <cfgpy-keypath-tuple>,
        'password': <cfgpy-keypath-tuple> 
       }

      where <cfgpy-keypath-tuple> is a tuple of keys 
      used to uniquely identify the location of the desired
      configuration element within the cfg dict contained
      in the CfgPy object.

   Native secure configuration

    Arguments: <host-identifier> <user-account-identifier>

     where 

      o <host-identifier> is an IPv4 or IPv6 address, hostname, or FQDN.
      o <user-account-identifer> is a user name

      For the sake of security, passwords should not appear in source code.

      Sftpy looks for password two places:

      1. environment variable named 'sftpypass_<host-identifier>'
      2. credentials file

      The credentials file should be located at ~/.sftpy/.creds
      Permissions on the credentials file must be set to 600.
      The format of the credentials file is:

      <host-identifier>:<user-identifier>:<password>

	"""
	def __init__(self, arg1, arg2):

		"""
		Default values are documented here 
		goal: support all of the knobs exposed by pexpect 
		"""
		self.session_handle = None
		self.timeout = 15
		self.maxreadbuf = 4096
		self.password = None
		# valid values: None, SESSDBGR, SESSDBGW, SESSDBGRW
		self.debug_session = SESSDBGRW
		self.username_prompt = 'ame:*'
		self.password_prompt = 'assword:*'
		self.prompt = 'sftp> '
		self.mode = MODE_BINARY
		self.state = STATE_START

		if type(arg1).__name__ == 'CfgPy':
			# arg2 must be dict containig host, user, password keys
			cfgobj = arg1
			host_element_path_tuple = arg2['host']
			user_element_path_tuple = arg2['user']
			password_element_path_tuple = arg2['password']
			self.host = cfgobj.read_element(host_element_path_tuple)
			self.user = cfgobj.read_element(user_element_path_tuple)
			self.password = cfgobj.read_element(password_element_path_tuple)
		else:
			host = arg1
			user = arg2
			self.host = host
			self.user = user
			if not self.get_credentials():
				raise ValueError(
					"failed to find password;\n No env var '%s', no creds file at %s" \
				   	% (self.credvarname, self.creds_filespec)
					)
				sys.exit(1)

		if not self.locate_sftp_client_program():
			raise ValueError('failed to locate SFTP client program')
			sys.exit(1)

		if DEBUGGING:
			print "host: %s" % (self.host)
			print "user: %s" % (self.user)

		self.login()
	
	def __enter__(self):

		return self

	def __exit__(self, type, value, traceback):

		pass

	def __repr__(self):

		s = '\n'
		for k in self.__dict__:
			s += "%5s%20s: %s\n" % (' ',k, self.__dict__[k])

		return s

	def locate_sftp_client_program(self):
		""" 
		Track down the sftp client program 
		Raise exception if not found.
		"""
		self.program = find_executable('sftp')
		if not self.program:
			raise IOError(
    			errno.ENOENT, 
    			os.strerror(errno.ENOENT), 
    			'sftp'
    			)
			return False
		return True

	def get_password_from_environment(self):
		""" 		
		  environment variable name:
		   'ftpypass_<host-identifier>'
		"""
		self.credvarname = 'sftpypass_%s' % (self.host)
		if self.credvarname in os.environ and os.environ[self.credvarname]:
			self.password = os.environ[self.credvarname]
			if DEBUGGING:
				print "found password in environment"
			return True
		return False

	def credentials_file_is_owned_by_current_user(self,credfile_stat):
		""" make sure file owned by current user """

		if not credfile_stat.st_uid == os.getuid():
			raise IOError("Credentials file %d not owned by current user" % (self.creds_filespec))
			return False
		return True

	def credentials_file_has_valid_permissions(self,credfile_stat):
		""" check permissions; should be 600 """

		if DEBUGGING:
			print "cred file perms:"
			pp.pprint(credfile_stat.st_mode)
		# owner must have read
		if not bool(credfile_stat.st_mode & stat.S_IRUSR):
			raise IOError("Incorrect file permissions on creds file %s, should be 0600" \
				% (self.creds_filespec))
			return False

		# bad if group has any access at all
		if bool(credfile_stat.st_mode & stat.S_IRWXG):
			raise IOError("Incorrect file permissions on creds file %s, should be 0600" \
				% (self.creds_filespec))
			return False

		# bad if others (world) have any access at all
		if bool(credfile_stat.st_mode & stat.S_IRWXO):
			raise IOError("Incorrect file permissions on creds file %s, should be 0600" \
				% (self.creds_filespec))
			return False

		return True

	def get_password_from_creds_file(self):
		""" The credentials file should be located at ~/.sftpy/.creds """

 		hdir = os.path.expanduser("~")
		self.creds_filespec = '%s/.sftpy/.creds' % (hdir)
		if DEBUGGING:
			print "seeking %s" % (self.creds_filespec)

		if os.path.isfile(self.creds_filespec):
			if DEBUGGING:
				print "found creds file: %s" % self.creds_filespec
			# get owner and permissions
			credfile_stat = os.stat(self.creds_filespec)
			if not self.credentials_file_is_owned_by_current_user(credfile_stat):
				return False

			if not self.credentials_file_has_valid_permissions(credfile_stat):
				return False

		try:
			with open(self.creds_filespec) as creds:
				""" 
				format of creds file is <host-identifier>:<user-identifier>:<password> 
				TODO: should strip spaces and use more robus searching/matching
				"""
				for line in creds.readlines():
					fields = line.split(':')
					if DEBUGGING:
						print line
						pp.pprint(fields)

					if fields[0] == self.host and fields[1] == self.user:
						self.password = fields[2]
						if DEBUGGING:
							print "found password in creds file %s" \
							  % self.creds_filespec
						return True

		except IOError as e:
			print "Unable to locate a password for %s on %s (creds file not found)" \
			  % (self.user,self.host)

		return False

	def get_credentials(self):
		""" 
		A utility file for tracking down the password to use.
		Check for environment variable first.
		If found, use that.
		Otherwise, fall back on credentials file.
		If credentials file not found, raise exception.
		"""

		if self.get_password_from_environment():
			return True

		if self.get_password_from_creds_file():
			return True

		return False

	def login(self):

		# TODO: populate this call with all of the knobs
		program_args = [ "%s@%s" % ( self.user, self.host ) ]
		self.session_handle = pexpect.spawn( 
			self.program, 
			args=program_args, 
			maxread=self.maxreadbuf, 
			timeout=self.timeout 
			)

		if self.debug_session == SESSDBGRW:
			self.session_handle.logfile = sys.stdout

		# how do we catch and report authentication failures?
		# as it currently is, this is DREADFUL
		self.session_handle.expect(self.password_prompt)
		self.session_handle.sendline(self.password)
		self.session_handle.expect(self.prompt)
		self.state = STATE_LOGGED_IN

		return

	def bye(self):

		self.session_handle.sendline('bye')
		self.session_handle.expect(pexpect.EOF)		

	def lcd(self, localpath):
		""" how can we verify the success of this? """

		# should validate that 
		self.session_handle.sendline('lcd %s' % localpath)
		self.session_handle.expect(self.prompt)

	def pwd(self):

		self.session_handle.sendline('pwd')
		self.session_handle.expect(self.prompt)

	def ls(self):

		self.session_handle.sendline('ls')
		self.session_handle.expect(self.prompt)

	def version(self):

		self.session_handle.sendline('version')
		self.session_handle.expect(self.prompt)

	def passive(self):
		""" WARNING! this command TOGGLES between active/passive! """

		self.session_handle.sendline('passive')
		self.session_handle.expect(self.prompt)	

	def rename(self, oldname, newname):

		self.session_handle.sendline('rename %s %s' % (oldname, newname))
		self.session_handle.expect(self.prompt)	

	def get(self, source_path):
		""" 
		we ought to do some validation of source_path 
		to prevent people from shooting themselves in the feet.
		"""
		self.session_handle.sendline('get %s' % (source_path))
		self.session_handle.expect(self.prompt)

	def mget(self, source_path):
		""" 
		raise warning if source_path doesn't look like 
		a filename pattern that contains asterisks
		"""
		self.session_handle.sendline('mget %s' % (source_path))
		self.session_handle.expect(self.prompt)

	def analyze_path(self, pathstr):
		""" 
		returns a dictionary containing
		 path_type - an integer constant
		 pathstr   - the original value
		 dirpart   - a (possibly empty) string
		 filepart  - a string devoid of slashes

		 if pathstr contains no slashes, it's assumed
		 that it is a filename pattern (i.e. filepart)
		"""

		result = {}
		result['pathstr'] = pathstr
		(result['dirpart'], result['filepart']) = os.path.split(pathstr)
		if dirpath:
			result['path_type'] = PATH_TYPE_COMPOUND
		else:
			"""
			empty dirpath means no slashes in pathstr,
			therefore pathstr is a filename pattern
			"""
			result['path_type'] = PATH_TYPE_FILEPART

		if DEBUGGING:
			pp.pprint(result)

		return result

	def beam_me_down(self, source_path):
		""" 
		'beam_me_down' fetches files with automatic get/mget detection 
		if the filepart of the path contains one or more wildcards ('*'),
		use mget. otherwise, use get.
		"""

		path_dict = self.analyze_path(source_path)

		# if dirpart is not empty, cd using dirpart first
		if path_dict['dirpart']:
			self.chdir(path_dict['dirpart'])

		filepart = path_dict['filepart']
		# I'd prefer to use substr here, re seems like overkill
		result = re.search(r'\*', filepart)
		if result is not None:
			self.mget(filepart)
		else:
			self.get(filepart)

	def set_xfer_mode(self, mode):

		modestr = None
		if mode == MODE_TEXT:
			modestr = 'text'
		elif mode == MODE_BINARY:
			modestr = 'binary'
		else:
			# check first to make sure 'mode' arg is even an integer!
			# raise value exception
			raise ValueError("Invalid mode constant: %d" % mode)

		self.session_handle.sendline('%s' % (modestr))
		self.session_handle.expect(self.prompt)

if __name__ == '__main__':
	# from sftpy.tools import Sftp

	cfgobj = CfgPy(FMT_INI, '.', ['./test.conf'])
	#cfgobj.set_file_extension('conf')
	cfgobj.load()
	print "host: {}".format(cfgobj.read_element(('sftpcredentials','host')))
	print "user: {}".format(cfgobj.read_element(('sftpcredentials','user')))
	print "password: {}".format(cfgobj.read_element(('sftpcredentials','password')))

	with Sftp(cfgobj, { 
		'host': ('sftpcredentials','host'), 
		'user': ('sftpcredentials','user'),
		'password': ('sftpcredentials','password')
		 }) as sftp:
		sftp.version()
		sftp.pwd()
		sftp.ls()
		sftp.bye()

"""
	with Sftp('ftp_sftp_test_server','sftptest') as sftp:
		sftp.version()
		sftp.pwd()
		sftp.ls()
		sftp.bye()
"""
