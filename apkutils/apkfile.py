#! /usr/bin/env python3
#coding=utf-8
import six

if six.PY3:
    import io
    import struct
    from zipfile import ZipFile as _ZipFile
    from zipfile import _EndRecData, _ECD_SIZE, _ECD_OFFSET, _ECD_COMMENT, _EndRecData, sizeCentralDir, structCentralDir, _CD_SIGNATURE, stringCentralDir, _CD_FILENAME_LENGTH, ZipInfo, _CD_EXTRA_FIELD_LENGTH, _CD_COMMENT_LENGTH,_CD_LOCAL_HEADER_OFFSET, MAX_EXTRACT_VERSION, _SharedFile, sizeFileHeader, structFileHeader, _FH_SIGNATURE, stringFileHeader, _FH_FILENAME_LENGTH, _FH_EXTRA_FIELD_LENGTH, ZipExtFile

    class ZipFile(_ZipFile):
        def _RealGetContents(self):
            """Read in the table of contents for the ZIP file."""
            fp = self.fp
            try:
                endrec = _EndRecData(fp)
            except OSError:
                raise BadZipFile("File is not a zip file")
            if not endrec:
                raise BadZipFile("File is not a zip file")
            if self.debug > 1:
                print(endrec)
            size_cd = endrec[_ECD_SIZE]             # bytes in central directory
            offset_cd = endrec[_ECD_OFFSET]         # offset of central directory
            self._comment = endrec[_ECD_COMMENT]    # archive comment

            # ---> APK文件只有一个，不可能存在额外数据。
            concat = 0

            if self.debug > 2:
                inferred = concat + offset_cd
                print("given, inferred, offset", offset_cd, inferred, concat)
            # self.start_dir:  Position of start of central directory
            self.start_dir = offset_cd + concat
            fp.seek(self.start_dir, 0)
            data = fp.read(size_cd)
            fp = io.BytesIO(data)
            total = 0
            while total < size_cd:
                centdir = fp.read(sizeCentralDir)
                if len(centdir) != sizeCentralDir:
                    raise BadZipFile("Truncated central directory")
                centdir = struct.unpack(structCentralDir, centdir)
                if centdir[_CD_SIGNATURE] != stringCentralDir:
                    raise BadZipFile("Bad magic number for central directory")
                if self.debug > 2:
                    print(centdir)
                filename = fp.read(centdir[_CD_FILENAME_LENGTH])
                flags = centdir[5]
                if flags & 0x800:
                    # UTF-8 file names extension
                    filename = filename.decode('utf-8')
                else:
                    # Historical ZIP filename encoding
                    filename = filename.decode('cp437')
                # Create ZipInfo instance to store file information
                x = ZipInfo(filename)
                x.extra = fp.read(centdir[_CD_EXTRA_FIELD_LENGTH])
                x.comment = fp.read(centdir[_CD_COMMENT_LENGTH])
                x.header_offset = centdir[_CD_LOCAL_HEADER_OFFSET]
                (x.create_version, x.create_system, x.extract_version, x.reserved,
                x.flag_bits, x.compress_type, t, d,
                x.CRC, x.compress_size, x.file_size) = centdir[1:12]
                if x.extract_version > MAX_EXTRACT_VERSION:
                    raise NotImplementedError("zip file version %.1f" %
                                            (x.extract_version / 10))
                x.volume, x.internal_attr, x.external_attr = centdir[15:18]
                # Convert date/time code to (year, month, day, hour, min, sec)
                x._raw_time = t
                x.date_time = ( (d>>9)+1980, (d>>5)&0xF, d&0x1F,
                                t>>11, (t>>5)&0x3F, (t&0x1F) * 2 )

                x._decodeExtra()
                x.header_offset = x.header_offset + concat
                self.filelist.append(x)
                self.NameToInfo[x.filename] = x

                # update total bytes read from central directory
                total = (total + sizeCentralDir + centdir[_CD_FILENAME_LENGTH]
                        + centdir[_CD_EXTRA_FIELD_LENGTH]
                        + centdir[_CD_COMMENT_LENGTH])

                if self.debug > 2:
                    print("total", total)

        def open(self, name, mode="r", pwd=None):
            """Return file-like object for 'name'."""
            if mode not in ("r", "U", "rU"):
                raise RuntimeError('open() requires mode "r", "U", or "rU"')
            if 'U' in mode:
                import warnings
                warnings.warn("'U' mode is deprecated",
                            DeprecationWarning, 2)
            if pwd and not isinstance(pwd, bytes):
                raise TypeError("pwd: expected bytes, got %s" % type(pwd))
            if not self.fp:
                raise RuntimeError(
                    "Attempt to read ZIP archive that was already closed")

            # Make sure we have an info object
            if isinstance(name, ZipInfo):
                # 'name' is already an info object
                zinfo = name
            else:
                # Get info object for name
                zinfo = self.getinfo(name)

            self._fileRefCnt += 1
            zef_file = _SharedFile(self.fp, zinfo.header_offset, self._fpclose, self._lock)
            try:
                # Skip the file header:
                fheader = zef_file.read(sizeFileHeader)
                if len(fheader) != sizeFileHeader:
                    raise BadZipFile("Truncated file header")
                fheader = struct.unpack(structFileHeader, fheader)
                if fheader[_FH_SIGNATURE] != stringFileHeader:
                    raise BadZipFile("Bad magic number for file header")

                fname = zef_file.read(fheader[_FH_FILENAME_LENGTH])
                if fheader[_FH_EXTRA_FIELD_LENGTH]:
                    zef_file.read(fheader[_FH_EXTRA_FIELD_LENGTH])

                if zinfo.flag_bits & 0x20:
                    # Zip 2.7: compressed patched data
                    raise NotImplementedError("compressed patched data (flag bit 5)")

                if zinfo.flag_bits & 0x40:
                    # strong encryption
                    raise NotImplementedError("strong encryption (flag bit 6)")

                if zinfo.flag_bits & 0x800:
                    # UTF-8 filename
                    fname_str = fname.decode("utf-8")
                else:
                    fname_str = fname.decode("cp437")

                if fname_str != zinfo.orig_filename:
                    raise BadZipFile(
                        'File name in directory %r and header %r differ.'
                        % (zinfo.orig_filename, fname))

                # ---> APK 不存在加密
                zd = None

                return ZipExtFile(zef_file, mode, zinfo, zd, True)
            except:
                zef_file.close()
                raise

if six.PY2:
    import cStringIO
    import struct
    from zipfile import ZipFile as _ZipFile
    from zipfile import _EndRecData, _ECD_SIZE, _ECD_OFFSET, _ECD_COMMENT, sizeCentralDir, stringCentralDir, structCentralDir, _CD_FILENAME_LENGTH, ZipInfo, _CD_EXTRA_FIELD_LENGTH, _CD_COMMENT_LENGTH, _CD_LOCAL_HEADER_OFFSET, sizeFileHeader, stringFileHeader, structFileHeader, _FH_FILENAME_LENGTH, _FH_EXTRA_FIELD_LENGTH, ZipExtFile
    class ZipFile(_ZipFile):
        def _RealGetContents(self):
            """Read in the table of contents for the ZIP file."""
            fp = self.fp
            endrec = _EndRecData(fp)
            if not endrec:
                raise BadZipfile("File is not a zip file")
            if self.debug > 1:
                print(endrec)
            size_cd = endrec[_ECD_SIZE]             # bytes in central directory
            offset_cd = endrec[_ECD_OFFSET]         # offset of central directory
            self.comment = endrec[_ECD_COMMENT]     # archive comment

            # ---> APK文件只有一个，不可能存在额外数据。
            concat = 0

            if self.debug > 2:
                inferred = concat + offset_cd
                print("given, inferred, offset", offset_cd, inferred, concat)
            # self.start_dir:  Position of start of central directory
            self.start_dir = offset_cd + concat
            fp.seek(self.start_dir, 0)
            data = fp.read(size_cd)
            fp = cStringIO.StringIO(data)
            total = 0
            while total < size_cd:
                centdir = fp.read(sizeCentralDir)
                if centdir[0:4] != stringCentralDir:
                    raise BadZipfile("Bad magic number for central directory")
                centdir = struct.unpack(structCentralDir, centdir)
                if self.debug > 2:
                    print(centdir)
                filename = fp.read(centdir[_CD_FILENAME_LENGTH])
                # Create ZipInfo instance to store file information
                x = ZipInfo(filename)
                x.extra = fp.read(centdir[_CD_EXTRA_FIELD_LENGTH])
                x.comment = fp.read(centdir[_CD_COMMENT_LENGTH])
                x.header_offset = centdir[_CD_LOCAL_HEADER_OFFSET]
                (x.create_version, x.create_system, x.extract_version, x.reserved,
                    x.flag_bits, x.compress_type, t, d,
                    x.CRC, x.compress_size, x.file_size) = centdir[1:12]
                x.volume, x.internal_attr, x.external_attr = centdir[15:18]
                # Convert date/time code to (year, month, day, hour, min, sec)
                x._raw_time = t
                x.date_time = ( (d>>9)+1980, (d>>5)&0xF, d&0x1F,
                                        t>>11, (t>>5)&0x3F, (t&0x1F) * 2 )

                x._decodeExtra()
                x.header_offset = x.header_offset + concat
                x.filename = x._decodeFilename()
                self.filelist.append(x)
                self.NameToInfo[x.filename] = x

                # update total bytes read from central directory
                total = (total + sizeCentralDir + centdir[_CD_FILENAME_LENGTH]
                        + centdir[_CD_EXTRA_FIELD_LENGTH]
                        + centdir[_CD_COMMENT_LENGTH])

                if self.debug > 2:
                    print("total", total)

        def open(self, name, mode="r", pwd=None):
            """Return file-like object for 'name'."""
            if mode not in ("r", "U", "rU"):
                raise RuntimeError('open() requires mode "r", "U", or "rU"')
            if not self.fp:
                raise RuntimeError("Attempt to read ZIP archive that was already closed")

            # Only open a new file for instances where we were not
            # given a file object in the constructor
            if self._filePassed:
                zef_file = self.fp
            else:
                zef_file = open(self.filename, 'rb')

            # Make sure we have an info object
            if isinstance(name, ZipInfo):
                # 'name' is already an info object
                zinfo = name
            else:
                # Get info object for name
                zinfo = self.getinfo(name)

            zef_file.seek(zinfo.header_offset, 0)

            # Skip the file header:
            fheader = zef_file.read(sizeFileHeader)
            if fheader[0:4] != stringFileHeader:
                raise BadZipfile("Bad magic number for file header")

            fheader = struct.unpack(structFileHeader, fheader)
            fname = zef_file.read(fheader[_FH_FILENAME_LENGTH])
            if fheader[_FH_EXTRA_FIELD_LENGTH]:
                zef_file.read(fheader[_FH_EXTRA_FIELD_LENGTH])

            if fname != zinfo.orig_filename:
                raise BadZipfile('File name in directory "%s" and header "%s" differ.' % (zinfo.orig_filename, fname))

            # ---> APK 不存在加密
            zd = None

            return  ZipExtFile(zef_file, mode, zinfo, zd)