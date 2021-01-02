/*
 Copyright (C) 2021 Karim Kanso

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

//system headers
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iconv.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <libgen.h>

// samba-dev headers
#include <tevent.h>
#include <talloc.h>
#include <credentials.h>
#include <param.h>
#include <dcerpc.h>

// pidl generated headers
#include "ndr_icpr.h"
#include "ndr_icpr_c.h"
#include "icpr.h"

uint16_t attrib[] = u"CertificateTemplate:User";
struct CERTTRANSBLOB s_attrib = {
    .cb = sizeof(attrib),
    .pb = (uint8_t*)attrib
};

const char* p_c_csr_file;
const char* p_c_user;
const char* p_c_pass;
const char* p_c_domain = ".";
const char* p_c_host;
const char* p_c_ca_name;
int32_t i_requestid = 0;

bool parse_args(int argc, char ** argv) {
  if (argc != 4) {
    printf(
        "usage: %s [domain/]user:pass@host caname "
        "[requestfile.csr|requestid]\n",
        basename(argv[0])
    );
    return false;
  }
  p_c_ca_name = argv[2];
  p_c_csr_file = argv[3];

  char *p_c_endptr = NULL;
  i_requestid = strtol(p_c_csr_file, &p_c_endptr, 0);
  if (*p_c_endptr) {
    i_requestid = 0;
  }

  if (!(p_c_host = strrchr(argv[1], '@'))) {
    puts("host not found");
    return false;
  }
  *((char*)p_c_host) = '\0';
  p_c_host++;

  if (!(p_c_pass = strchr(argv[1], ':'))) {
    puts("pass not found");
    return false;
  }
  *((char*)p_c_pass) = '\0';
  p_c_pass++;

  if (!(p_c_user = strchr(argv[1], '/'))) {
    p_c_user = argv[1];
  } else {
    *((char*)p_c_user) = '\0';
    p_c_user++;
    p_c_domain = argv[1];
  }
  return true;
}

int main(int argc, char ** argv) {
  TALLOC_CTX *frame = talloc_init("icpr");
  NTSTATUS nt_status;
  struct dcerpc_pipe *p;
  struct tevent_context *ev_ctx = tevent_context_init(frame);
  struct loadparm_context *lp_ctx = loadparm_init(frame);
  struct CERTTRANSBLOB s_csr = {0, 0};
  struct stat s_stat;
  char c_binding[128];

  if (!parse_args(argc, argv)) {
    goto done;
  }

  if (!i_requestid) {
    int i_fd_csr = open(p_c_csr_file, O_RDONLY);
    if (i_fd_csr == -1) {
      perror("open csr");
      goto done;
    }
    if (fstat(i_fd_csr, &s_stat)) {
      perror("stat csr");
      close(i_fd_csr);
      goto done;
    }
    s_csr.cb = s_stat.st_size;
    s_csr.pb = (uint8_t*)malloc(s_stat.st_size);
    if (!s_csr.pb) {
      printf("malloc fail\n");
      close(i_fd_csr);
      goto done;
    }
    read(i_fd_csr, s_csr.pb, s_csr.cb);
    close(i_fd_csr);
    i_fd_csr = -1;
  } else {
    s_attrib.cb = 0;
    s_attrib.pb = NULL;
  }

  dcerpc_init();

  if(ev_ctx == NULL) {
    printf("tevent_context_init failed\n");
    goto done;
  }
  // copied from tevent_s4.c, not sure if required,
  // however it requires -DTEVENT_DEPRECATED
  // tevent_loop_allow_nesting(ev_ctx);

  if (lpcfg_configfile(lp_ctx) == NULL) {
    lpcfg_load_default(lp_ctx);
  }

  // uncomment to enable debug messages from dcerpc lib
  lpcfg_set_cmdline(lp_ctx, "log level", "99");

  struct cli_credentials *cred = cli_credentials_init(frame);

  if (!cli_credentials_set_username(cred, p_c_user, CRED_SPECIFIED)) {
    printf("cli_credentials_set_username failed\n");
    goto done;
  }

  if (!cli_credentials_set_password(cred, p_c_pass, CRED_SPECIFIED)) {
    printf("cli_credentials_set_password failed\n");
    goto done;
  }
  // guess sets defaults, parses env vars and reads config
  //cli_credentials_guess(cred, lp_ctx);
  // however, instead it looks sufficient to set items as follows
  cli_credentials_set_realm(cred, p_c_domain, CRED_SPECIFIED);
  cli_credentials_set_domain(cred, p_c_domain, CRED_SPECIFIED);
  cli_credentials_set_workstation(cred, "WKSTN", CRED_SPECIFIED);

  // "ntlm,seal" sets the AUTH_LEVEL and AUTH_TYPE for the bind
  snprintf(
      c_binding,
      sizeof(c_binding),
      "ncacn_ip_tcp:%s[ntlm,seal]",
      p_c_host
  );
  nt_status = dcerpc_pipe_connect(
      frame,
      &p,
      //"ncacn_np:10.10.10.103[\\pipe\\cert,ntlm,seal]",
      c_binding,
      &ndr_table_ICertPassage,
      cred,
      ev_ctx,
      lp_ctx
  );
  printf("dcerpc_pipe_connect: %x\n", NT_STATUS_V(nt_status));
  if (!NT_STATUS_IS_OK(nt_status)) {
      goto done;
  }

  int32_t disposition = 0;
  int32_t result = 0;
  struct CERTTRANSBLOB results[3] = {{0,0},{0,0},{0,0}};
  nt_status = dcerpc_CertServerRequest(
      p->binding_handle,
      frame,
      0             /*  dwFlags[in]  */,
      p_c_ca_name   /* pwszAuthority [in] [charset(UTF16),unique] */,
      &i_requestid  /* pdwRequestId [in,out] [ref] */,
      &disposition  /* pdwDisposition [out] [ref] */,
      &s_attrib     /* pctbAttribs [in] [ref] */,
      &s_csr        /* pctbRequest [in] [ref] */,
      results + 0   /* pctbCert [out] [ref] */,
      results + 1   /* pctbEncodedCert [out] [ref] */,
      results + 2   /* pctbDispositionMessage [out] [ref] */,
      &result
  );

  printf("dcerpc_CertServerRequest: %x\n", NT_STATUS_V(nt_status));
  if (!NT_STATUS_IS_OK(nt_status)) {
      goto done;
  }

  printf("result: 0x%x\n", result);
  printf("req id: %d\n", i_requestid);
  if (result == 0) {
    iconv_t cd = iconv_open ("utf8", "utf16");
    char disp[results[2].cb / 2];
    char *s = (char*)results[2].pb;
    size_t zs = results[2].cb;
    char *d = disp;
    size_t zd = results[2].cb / 2;
    iconv(cd, &s, &zs, &d, &zd);
    iconv_close(cd);
    printf("Disposition [%x]: %s\n", disposition, disp);
    switch (disposition) {
    case 3: // issued
    case 5: // under submission
    case 0: // ?
      break;
    default:
      printf("  check disposition code for specific error details.\n");
    }
  }
  if (results[1].cb) {
    printf("Certificate [DER]: ");
    for (int j = 0; j<results[1].cb; j++) {
      printf("%02x", results[1].pb[j]);
    }
    printf("\n");
  }
  /* for (int i = 0; i < 2; i++) { */
  /*   printf("size: %d\n", results[i].cb); */
  /*   if (!results[i].cb) { */
  /*     continue; */
  /*   } */
  /*   printf("data: "); */
  /*   for (int j = 0; j<results[i].cb; j++) { */
  /*     printf("%02x", results[i].pb[j]); */
  /*   } */
  /*   printf("\n"); */
  /* } */

 done:
    if (s_csr.pb) {
      free(s_csr.pb);
      s_csr.pb = NULL;
    }
    TALLOC_FREE(frame);
    return 0;
}
