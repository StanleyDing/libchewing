/**
 * test-json-export.c
 *
 * Copyright (c) 2014
 *      libchewing Core Team. See ChangeLog for details.
 *
 * See the file "COPYING" for information on usage and redistribution
 * of this file.
 */

#ifdef HAVE_CONFIG_H
#    include <config.h>
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "chewing.h"
#include "plat_types.h"
#include "testhelper.h"
#include "json.h"

FILE *fd;

void test_export_file()
{
    ChewingContext *ctx;
    int ret;

    const char phrase[] = "\xE6\xB8\xAC\xE8\xA9\xA6" /* 測試 */ ;
    const char bopomofo[] = "\xE3\x84\x98\xE3\x84\x9C\xCB\x8B \xE3\x84\x95\xCB\x8B" /* ㄘㄜˋ ㄕˋ */ ;

    clean_userphrase();

    ctx = chewing_new();
    start_testcase(ctx, fd);

    ret = chewing_userphrase_add(ctx, phrase, bopomofo);
    ok(ret == 1, "chewing_userphrase_add() return value `%d' shall be `%d'", ret, 1);

    ret = chewing_userphrase_export(ctx, NULL);
    ok(ret == 1, "chewing_userphrase_export() return value `%d' shall be `%d'", ret, 1);

    chewing_delete(ctx);
}

void test_import_file()
{
    ChewingContext *ctx;
    int ret;

    const char phrase[] = "\xE6\xB8\xAC\xE8\xA9\xA6" /* 測試 */ ;
    const char bopomofo[] = "\xE3\x84\x98\xE3\x84\x9C\xCB\x8B \xE3\x84\x95\xCB\x8B" /* ㄘㄜˋ ㄕˋ */ ;

    clean_userphrase();

    ctx = chewing_new();
    start_testcase(ctx, fd);

    ret = chewing_userphrase_import(ctx, "userphrase.json");
    ok(ret == 1, "chewing_userphrase_import() return value `%d' shall be `%d'", ret, 1);

    ret = chewing_userphrase_lookup(ctx, phrase, bopomofo);
    ok(ret == 1, "chewing_lookup() return value `%d' shall be `%d'", ret, 1);

    chewing_delete(ctx);
}

int main(int argc, char *argv[])
{
    char *logname;
    int ret;

    putenv("CHEWING_PATH=" CHEWING_DATA_PREFIX);
    putenv("CHEWING_USER_PATH=" TEST_HASH_DIR);

    ret = asprintf(&logname, "%s.log", argv[0]);
    if (ret == -1)
        return -1;
    fd = fopen(logname, "w");
    assert(fd);
    free(logname);

    test_export_file();
    test_import_file();

    fclose(fd);

    return exit_status();
}
