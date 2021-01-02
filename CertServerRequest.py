#!/usr/bin/env python3

# Copyright (C) 2021 Karim Kanso
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRPOINTER, NDRSTRUCT, NDRCALL, NULL
from impacket.dcerpc.v5.dtypes import ULONG, LPBYTE, DWORD, LPWSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException
import impacket.dcerpc.v5.rpcrt as rpcrt
from impacket.dcerpc.v5.epm import hept_map
import argparse

parser = argparse.ArgumentParser(
    description='POC to execute ICertPassage::CertServerRequest rpc'
)
parser.add_argument(
    'host',
    metavar='IP',
    help='ip address of server'
)
parser.add_argument(
    'user',
    metavar='USR',
    help='username for authentication'
)
parser.add_argument(
    'password',
    metavar='PWD',
    help='password for authentication'
)
parser.add_argument(
    'caname',
    metavar='CA',
    help='name of certification authority'
)
parser.add_argument(
    'csr',
    metavar='CSR',
    type=lambda x: open(x, 'rb').read(),
    help='file pkcs#10 der coded csr to send'
)
parser.add_argument(
    '--named-pipe',
    dest='tcp',
    action='store_false',
    help='used named pipe instead of tcp transport'
)
args = parser.parse_args()

## below is definition from MS-ICPR (and MS-WCCE):

# typedef struct _CERTTRANSBLOB {
#     ULONG                       cb;
#     [size_is(cb), unique] BYTE *pb;
# } CERTTRANSBLOB;
#
# [
#     uuid(91ae6020-9e3c-11cf-8d7c-00aa00c091be),
#     pointer_default(unique)
# ]
# interface ICertPassage
# {
#     DWORD CertServerRequest(
# [in]                        handle_t        h,
# [in]                        DWORD           dwFlags,
# [in, string, unique] const  wchar_t         *pwszAuthority,
# [in, out, ref]              DWORD           *pdwRequestId,
# [out]                       DWORD           *pdwDisposition,
# [in, ref]            const  CERTTRANSBLOB   *pctbAttribs,
# [in, ref]            const  CERTTRANSBLOB   *pctbRequest,
# [out, ref]                  CERTTRANSBLOB   *pctbCert,
# [out, ref]                  CERTTRANSBLOB   *pctbEncodedCert,
# [out, ref]                  CERTTRANSBLOB   *pctbDispositionMessage);
# }

class CERTTRANSBLOB(NDRSTRUCT):
    structure = (
        ('cb', ULONG),
        ('pb', LPBYTE),
    )

class CertServerRequest(NDRCALL):
    opnum = 0
    structure = (
        ('dwFlags', DWORD),
        ('pwszAuthority', LPWSTR),
        ('pdwRequestId', DWORD),
        ('pctbAttribs', CERTTRANSBLOB),
        ('pctbRequest', CERTTRANSBLOB),
    )

class CertServerRequestResponse(NDRCALL):
    structure = (
        ('pdwRequestId', DWORD),
        ('pdwDisposition', DWORD),
        ('pctbCert', CERTTRANSBLOB),
        ('pctbEncodedCert', CERTTRANSBLOB),
        ('pctbDispositionMessage', CERTTRANSBLOB),
        ('result', DWORD),
    )

def DCERPCSessionError(error_code, packet=None):
    print(f'[E] error: {error_code:x}')
    sys.exit(1)

# lookup interface in epm
binding = hept_map(
    args.host,
    remoteIf = uuidtup_to_bin(('91AE6020-9E3C-11CF-8D7C-00AA00C091BE','0.0')),
    protocol='ncacn_ip_tcp' if args.tcp else 'ncacn_np'
)

print(f'[*] using binding string: {binding}')

rpc = transport.DCERPCTransportFactory(binding)
# typically the binding string will be of one of the following forms:
#rpc = transport.DCERPCTransportFactory('ncacn_np:192.168.57.133[\pipe\cert]')
#rpc = transport.DCERPCTransportFactory('ncacn_ip_tcp:192.168.57.133[49702]')
rpc.set_credentials(args.user, args.password)
dce = rpc.get_dce_rpc()
dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
dce.connect()
x = dce.bind(uuidtup_to_bin(('91AE6020-9E3C-11CF-8D7C-00AA00C091BE','0.0')))

request = CertServerRequest()
request['dwFlags'] = 0x010000 # specifies pkcs#10 der csr
request['pwszAuthority'] = f'{args.caname}\x00'
request['pdwRequestId'] = 0 # change this to retrive an already generated cert

request['pctbAttribs']['pb'] = list('CertificateTemplate:User\x00'.encode('utf-16le'))
request['pctbAttribs']['cb'] = len(request['pctbAttribs']['pb'])
request['pctbRequest']['pb'] = list(args.csr)
request['pctbRequest']['cb'] = len(args.csr)

try:
    response = dce.request(request)
except DCERPCException as e:
    print(e)
    sys.exit(1)

dce.disconnect()

if result := response["result"]:
    print(f'[E] error code {result:x}')
    sys.exit(1)

print(f'[*] request id: {response["pdwRequestId"]}')
print(
    f'[*] Disposition [{response["pdwDisposition"]}]: ' +
    b"".join(response["pctbDispositionMessage"]["pb"]).decode("utf-16le")
)
if response["pctbEncodedCert"]["cb"]:
    print('[*] Certificate [der]: ', end='')
    for b in response["pctbEncodedCert"]["pb"]:
        print(f'{b[0]:02x}', end='')
    print()
