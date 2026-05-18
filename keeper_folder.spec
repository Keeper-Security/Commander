# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

import os

a = Analysis(['keeper.py'],
             pathex=['.'],
             binaries=[],
             datas=[(os.path.join('keepercommander', 'importer', 'keepass', 'template.kdbx'),
                os.path.join('keepercommander', 'importer', 'keepass')),
                ('public_suffix_list.dat', 'fido2'),
                   ],
             hiddenimports=['keepercommander.importer.json',
                            'keepercommander.importer.csv',
                            'keepercommander.importer.keepass',
                            'keepercommander.importer.lastpass',
                            'keepercommander.plugins',
                            'keepercommander.yubikey',
                            'keepercommander.keeper_drive.common',
                            'keepercommander.keeper_drive.permissions',
                            'keepercommander.keeper_drive.folder_api',
                            'keepercommander.keeper_drive.record_api',
                            'keepercommander.keeper_drive.folder_record_api',
                            'keepercommander.keeper_drive.removal_api',
                            'keepercommander.keeper_drive.sync',
                            ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='keeper',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          console=True)
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='keeper')
