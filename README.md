# sftpy
A python SFTP module that supports mget-style filename globby patterns

Have you ever longed for mget in a python SFTP module? Leave those kludgy workarounds behind. We got it.

### Security

Passwords shouldn't be embedded in source code. Ideally, passwords should be provided either
* In a hidden file owned by the user with file permissions that only permit the owner to see it, or
* In an environment variable.

That's how it *should* work, so that's how ftpy *does* work.

The sftpy password file:

1. ~/.sftpy/.creds
2. Lines contain three colon-delimited fields: <host>:<user>:<password>
3. Must be chmod 0600 (only owner has access to it)

Example

```
$ cat ~/.sftpy/.creds
sftp_test_server:sftpuser:thisisnotarealpassword
```

### Pythonic idioms

```python
  with Sftpy('sftp_test_server','sftpuser') as sftp:
      sftp.version()
      sftp.pwd()
      sftp.ls()
      sftp.bye()
```

