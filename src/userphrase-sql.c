/**
 * userphrase-sql.c
 *
 * Copyright (c) 2014
 *      libchewing Core Team. See ChangeLog for details.
 *
 * See the file "COPYING" for information on usage and redistribution
 * of this file.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "chewing-utf8-util.h"
#include "dict-private.h"
#include "tree-private.h"
#include "userphrase-private.h"
#include "private.h"
#include "key2pho-private.h"
#include "json.h"

static int UserBindPhone(ChewingData *pgdata, int index, const uint16_t phoneSeq[], int len)
{
    int i;
    int ret;

    assert(pgdata);
    assert(phoneSeq);

    if (len > MAX_PHRASE_LEN) {
        LOG_WARN("phoneSeq length %d > MAX_PHRASE_LEN(%d)", len, MAX_PHRASE_LEN);
        return -1;
    }

    ret = sqlite3_bind_int(pgdata->static_data.stmt_userphrase[index], BIND_USERPHRASE_LENGTH, len);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_bind_int returns %d", ret);
        return ret;
    }

    for (i = 0; i < len; ++i) {
        ret = sqlite3_bind_int(pgdata->static_data.stmt_userphrase[index], BIND_USERPHRASE_PHONE_0 + i, phoneSeq[i]);
        if (ret != SQLITE_OK) {
            LOG_ERROR("sqlite3_bind_int returns %d", ret);
            return ret;
        }
    }

    for (i = len; i < MAX_PHRASE_LEN; ++i) {
        ret = sqlite3_bind_int(pgdata->static_data.stmt_userphrase[index], BIND_USERPHRASE_PHONE_0 + i, 0);
        if (ret != SQLITE_OK) {
            LOG_ERROR("sqlite3_bind_int returns %d", ret);
            return ret;
        }
    }

    return SQLITE_OK;
}


/* load the orginal frequency from the static dict */
static int LoadOriginalFreq(ChewingData *pgdata, const uint16_t phoneSeq[], const char wordSeq[], int len)
{
    const TreeType *tree_pos;
    int retval;
    Phrase *phrase = ALC(Phrase, 1);

    tree_pos = TreeFindPhrase(pgdata, 0, len - 1, phoneSeq);
    if (tree_pos) {
        GetPhraseFirst(pgdata, phrase, tree_pos);
        do {
            /* find the same phrase */
            if (!strcmp(phrase->phrase, wordSeq)) {
                retval = phrase->freq;
                free(phrase);
                return retval;
            }
        } while (GetVocabNext(pgdata, phrase));
    }

    free(phrase);
    return FREQ_INIT_VALUE;
}

/* find the maximum frequency of the same phrase */
static int LoadMaxFreq(ChewingData *pgdata, const uint16_t phoneSeq[], int len)
{
    const TreeType *tree_pos;
    Phrase *phrase = ALC(Phrase, 1);
    int maxFreq = FREQ_INIT_VALUE;
    int max_userphrase_freq;
    int ret;

    tree_pos = TreeFindPhrase(pgdata, 0, len - 1, phoneSeq);
    if (tree_pos) {
        GetPhraseFirst(pgdata, phrase, tree_pos);
        do {
            if (phrase->freq > maxFreq)
                maxFreq = phrase->freq;
        } while (GetVocabNext(pgdata, phrase));
    }
    free(phrase);

    assert(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_GET_MAX_FREQ]);

    ret = UserBindPhone(pgdata, STMT_USERPHRASE_GET_MAX_FREQ, phoneSeq, len);
    if (ret != SQLITE_OK) {
        LOG_ERROR("UserBindPhone returns %d", ret);
        return maxFreq;
    }

    ret = sqlite3_step(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_GET_MAX_FREQ]);
    if (ret != SQLITE_ROW)
        return maxFreq;

    ret = sqlite3_reset(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_GET_MAX_FREQ]);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_reset returns %d", ret);
        return maxFreq;
    }

    max_userphrase_freq = sqlite3_column_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_GET_MAX_FREQ],
                                             SQL_STMT_USERPHRASE[STMT_USERPHRASE_GET_MAX_FREQ].column
                                             [COLUMN_USERPHRASE_USER_FREQ]);

    if (max_userphrase_freq > maxFreq)
        maxFreq = max_userphrase_freq;

    return maxFreq;
}

/* compute the new updated freqency */
static int UpdateFreq(int freq, int maxfreq, int origfreq, int deltatime)
{
    int delta;

    /* Short interval */
    if (deltatime < 4000) {
        delta = (freq >= maxfreq) ?
            min((maxfreq - origfreq) / 5 + 1,
                SHORT_INCREASE_FREQ) : max((maxfreq - origfreq) / 5 + 1, SHORT_INCREASE_FREQ);
        return min(freq + delta, MAX_ALLOW_FREQ);
    }
    /* Medium interval */
    else if (deltatime < 50000) {
        delta = (freq >= maxfreq) ?
            min((maxfreq - origfreq) / 10 + 1,
                MEDIUM_INCREASE_FREQ) : max((maxfreq - origfreq) / 10 + 1, MEDIUM_INCREASE_FREQ);
        return min(freq + delta, MAX_ALLOW_FREQ);
    }
    /* long interval */
    else {
        delta = max((freq - origfreq) / 5, LONG_DECREASE_FREQ);
        return max(freq - delta, origfreq);
    }
}

static int GetCurrentLifeTime(ChewingData *pgdata)
{
    return pgdata->static_data.new_lifetime;
}

static void LogUserPhrase(ChewingData *pgdata,
                          const uint16_t phoneSeq[],
                          const char wordSeq[], int orig_freq, int max_freq, int user_freq, int recent_time)
{
    /* Size of each phone is len("0x1234 ") = 7 */
    char buf[7 * MAX_PHRASE_LEN + 1] = { 0 };
    int i;

    for (i = 0; i < MAX_PHRASE_LEN; ++i) {
        if (phoneSeq[i] == 0)
            break;
        snprintf(buf + 7 * i, 7 + 1, "%#06x ", phoneSeq[i]);
    }

    LOG_INFO("userphrase %s, phone = %s, orig_freq = %d, max_freq = %d, user_freq = %d, recent_time = %d",
             wordSeq, buf, orig_freq, max_freq, user_freq, recent_time);
}

static int ToRowObj(void *array_obj, int column_num,
                    char **text, char **column_name)
{
    int i;
    json_object *row_obj;

    row_obj = json_object_new_object();
    if (!row_obj) {
        return 1;
    }

    /* First (column_num - 1) columns of database is of type INTEGER */
    for (i = 0; i < 16; ++i) {
        json_object_object_add(row_obj, column_name[i], json_object_new_int(atoi(text[i])));
    }
    /* The last column is of type TEXT */
    json_object_object_add(row_obj, column_name[i], json_object_new_string(text[i]));

    json_object_array_add(array_obj, row_obj);

    return 0;
}

void UserUpdatePhraseBegin(ChewingData *pgdata)
{
    sqlite3_exec(pgdata->static_data.db, "BEGIN", 0, 0, 0);
}

int UserUpdatePhrase(ChewingData *pgdata, const uint16_t phoneSeq[], const char wordSeq[])
{
    int ret;
    int action;
    int phone_len;
    int word_len;

    int orig_freq;
    int max_freq;
    int user_freq;
    int recent_time;
    int orig_time;

    assert(pgdata);
    assert(phoneSeq);
    assert(wordSeq);

    phone_len = GetPhoneLen(phoneSeq);
    word_len = ueStrLen(wordSeq);

    if (phone_len != word_len) {
        LOG_WARN("Do not update userphrase because phoneSeq length %d != wordSeq length %d", phone_len, word_len);
        return USER_UPDATE_FAIL;
    }

    if (word_len > MAX_PHRASE_LEN) {
        LOG_WARN("wordSeq length %d > MAX_PHRASE_LEN (%d)", word_len, MAX_PHRASE_LEN);
        return USER_UPDATE_FAIL;
    }

    ret = UserBindPhone(pgdata, STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE, phoneSeq, phone_len);
    if (ret != SQLITE_OK) {
        LOG_ERROR("UserBindPhone returns %d", ret);
        action = USER_UPDATE_FAIL;
        goto end;
    }

    ret = sqlite3_bind_text(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE],
                            BIND_USERPHRASE_PHRASE, wordSeq, -1, SQLITE_STATIC);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_bind_text returns %d", ret);
        action = USER_UPDATE_FAIL;
        goto end;
    }

    recent_time = GetCurrentLifeTime(pgdata);

    ret = sqlite3_step(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE]);
    if (ret == SQLITE_ROW) {
        action = USER_UPDATE_MODIFY;

        orig_freq = sqlite3_column_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE],
                                       SQL_STMT_USERPHRASE[STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE].column
                                       [COLUMN_USERPHRASE_ORIG_FREQ]);

        max_freq = LoadMaxFreq(pgdata, phoneSeq, phone_len);

        user_freq = sqlite3_column_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE],
                                       SQL_STMT_USERPHRASE[STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE].column
                                       [COLUMN_USERPHRASE_USER_FREQ]);

        orig_time = sqlite3_column_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE],
                                       SQL_STMT_USERPHRASE[STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE].column
                                       [COLUMN_USERPHRASE_TIME]);

        user_freq = UpdateFreq(user_freq, max_freq, orig_freq, recent_time - orig_time);
    } else {
        action = USER_UPDATE_INSERT;

        orig_freq = LoadOriginalFreq(pgdata, phoneSeq, wordSeq, word_len);
        max_freq = LoadMaxFreq(pgdata, phoneSeq, phone_len);
        user_freq = orig_freq;
    }

    assert(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_UPSERT]);

    ret = sqlite3_bind_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_UPSERT],
                           BIND_USERPHRASE_TIME, recent_time);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_bind_int returns %d", ret);
        action = USER_UPDATE_FAIL;
        goto end;
    }

    ret = sqlite3_bind_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_UPSERT],
                           BIND_USERPHRASE_USER_FREQ, user_freq);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_bind_int returns %d", ret);
        action = USER_UPDATE_FAIL;
        goto end;
    }

    ret = sqlite3_bind_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_UPSERT],
                           BIND_USERPHRASE_MAX_FREQ, max_freq);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_bind_int returns %d", ret);
        action = USER_UPDATE_FAIL;
        goto end;
    }

    ret = sqlite3_bind_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_UPSERT],
                           BIND_USERPHRASE_ORIG_FREQ, orig_freq);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_bind_int returns %d", ret);
        action = USER_UPDATE_FAIL;
        goto end;
    }

    ret = UserBindPhone(pgdata, STMT_USERPHRASE_UPSERT, phoneSeq, phone_len);
    if (ret != SQLITE_OK) {
        LOG_ERROR("UserBindPhone returns %d", ret);
        action = USER_UPDATE_FAIL;
        goto end;
    }

    ret = sqlite3_bind_text(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_UPSERT],
                            BIND_USERPHRASE_PHRASE, wordSeq, -1, SQLITE_STATIC);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_bind_text returns %d", ret);
        action = USER_UPDATE_FAIL;
        goto end;
    }

    ret = sqlite3_step(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_UPSERT]);
    if (ret != SQLITE_DONE) {
        LOG_ERROR("sqlite3_step returns %d", ret);
        action = USER_UPDATE_FAIL;
        goto end;
    }

    LogUserPhrase(pgdata, phoneSeq, wordSeq, orig_freq, max_freq, user_freq, recent_time);

  end:
    ret = sqlite3_reset(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_UPSERT]);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_reset returns %d", ret);
    }

    ret = sqlite3_reset(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE_PHRASE]);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_reset returns %d", ret);
    }

    return action;
}

void UserUpdatePhraseEnd(ChewingData *pgdata)
{
    sqlite3_exec(pgdata->static_data.db, "END", 0, 0, 0);
}

int UserRemovePhrase(ChewingData *pgdata, const uint16_t phoneSeq[], const char wordSeq[])
{
    int ret;
    int len;
    int affected = 0;

    assert(pgdata);
    assert(phoneSeq);
    assert(wordSeq);

    assert(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_DELETE]);

    len = GetPhoneLen(phoneSeq);
    ret = UserBindPhone(pgdata, STMT_USERPHRASE_DELETE, phoneSeq, len);
    if (ret != SQLITE_OK) {
        LOG_ERROR("UserBindPhone returns %d", ret);
        goto end;
    }

    ret = sqlite3_bind_text(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_DELETE],
                            BIND_USERPHRASE_PHRASE, wordSeq, -1, SQLITE_STATIC);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_bind_text returns %d", ret);
        goto end;
    }

    ret = sqlite3_step(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_DELETE]);
    if (ret != SQLITE_DONE) {
        LOG_ERROR("sqlite3_step returns %d", ret);
        goto end;
    }

    affected = sqlite3_changes(pgdata->static_data.db);

  end:
    ret = sqlite3_reset(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_DELETE]);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_reset returns %d", ret);
    }

    return affected;
}


UserPhraseData *UserGetPhraseFirst(ChewingData *pgdata, const uint16_t phoneSeq[])
{
    int ret;
    int len;

    assert(pgdata);
    assert(phoneSeq);

    assert(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE]);
    ret = sqlite3_reset(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE]);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_reset returns %d", ret);
        return NULL;
    }

    len = GetPhoneLen(phoneSeq);
    ret = UserBindPhone(pgdata, STMT_USERPHRASE_SELECT_BY_PHONE, phoneSeq, len);
    if (ret != SQLITE_OK) {
        LOG_ERROR("UserBindPhone returns %d", ret);
        return NULL;
    }

    return UserGetPhraseNext(pgdata, phoneSeq);
}

UserPhraseData *UserGetPhraseNext(ChewingData *pgdata, const uint16_t phoneSeq[])
{
    int ret;

    assert(pgdata);
    assert(phoneSeq);

    ret = sqlite3_step(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE]);
    if (ret != SQLITE_ROW)
        return NULL;

    /* FIXME: shall not remove const here. */
    pgdata->userphrase_data.wordSeq =
        (char *) sqlite3_column_text(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE],
                                     SQL_STMT_USERPHRASE[STMT_USERPHRASE_SELECT_BY_PHONE].column
                                     [COLUMN_USERPHRASE_PHRASE]);
    pgdata->userphrase_data.phoneSeq = (uint16_t *) phoneSeq;

    pgdata->userphrase_data.recentTime =
        sqlite3_column_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE],
                           SQL_STMT_USERPHRASE[STMT_USERPHRASE_SELECT_BY_PHONE].column[COLUMN_USERPHRASE_TIME]);

    pgdata->userphrase_data.userfreq =
        sqlite3_column_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE],
                           SQL_STMT_USERPHRASE[STMT_USERPHRASE_SELECT_BY_PHONE].column[COLUMN_USERPHRASE_USER_FREQ]);

    pgdata->userphrase_data.maxfreq =
        sqlite3_column_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE],
                           SQL_STMT_USERPHRASE[STMT_USERPHRASE_SELECT_BY_PHONE].column[COLUMN_USERPHRASE_MAX_FREQ]);

    pgdata->userphrase_data.origfreq =
        sqlite3_column_int(pgdata->static_data.stmt_userphrase[STMT_USERPHRASE_SELECT_BY_PHONE],
                           SQL_STMT_USERPHRASE[STMT_USERPHRASE_SELECT_BY_PHONE].column[COLUMN_USERPHRASE_ORIG_FREQ]);

    return &pgdata->userphrase_data;
}

void UserGetPhraseEnd(ChewingData *pgdata, const uint16_t phoneSeq[])
{
    /* FIXME: Remove this */
}

void IncreaseLifeTime(ChewingData *pgdata)
{
    ++pgdata->static_data.new_lifetime;
}

int ExportToJson(ChewingData *pgdata, const char *path)
{
    const char filename[] = "userphrase.json";

    int ret;
    int result;
    FILE *fp = NULL;
    char *filepath = NULL;
    char *tmp;
    struct json_object *json_obj = NULL;
    struct json_object *array_obj = NULL;

    assert(pgdata);
    assert(path);

    tmp = getenv("CHEWING_USER_PATH");
    if (tmp && access(tmp, W_OK) == 0) {
        ret = asprintf(&filepath, "%s/%s", tmp, filename);
        if (ret == -1) {
            LOG_ERROR("asprintf returns %d", ret);
            result = EXPORT_FAIL;
            goto end;
        }
    }

    fp = fopen(filepath, "w");
    if (fp == NULL) {
        LOG_ERROR("can't open file to export");
        result = EXPORT_FAIL;
        goto end;
    }

    json_obj = json_object_new_object();
    array_obj = json_object_new_array();

    if (!json_obj || !array_obj) {
        LOG_ERROR("fail to create json object");
        result = EXPORT_FAIL;
        goto end;
    }

    ret = sqlite3_exec(pgdata->static_data.db,
                       "SELECT * FROM userphrase_v1",
                       ToRowObj, array_obj, NULL);
    if (ret != SQLITE_OK) {
        LOG_ERROR("sqlite3_exec returns %d", ret);
        result = EXPORT_FAIL;
        goto end;
    }

    json_object_object_add(json_obj, "phrase", array_obj);
    fprintf(fp, "%s\n", json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY));

    /* free the json_obj */
    json_object_put(json_obj);

    result = EXPORT_SUCCESS;

  end:
    fclose(fp);
    free(filepath);

    return result;
}

int ImportFromJson(ChewingData *pgdata, const char *path)
{
    const int MAX_LEN = 1024;
    const char *phones[] = {
        "phone_0", "phone_1", "phone_2", "phone_3",
        "phone_4", "phone_5", "phone_6", "phone_7",
        "phone_8", "phone_9", "phone_10"
    };

    int i, j;
    int ret;
    int phrase_length, array_length;
    FILE *fp;
    char str[MAX_LEN];
    const char *word_seq;
    uint16_t *phone_buf = NULL;
    struct json_object *json_obj = NULL;
    struct json_object *phrase_obj;
    struct json_object *array_obj;
    struct json_object *tmp_obj;
    struct json_tokener *tok;
    enum json_tokener_error jerr;

    assert(pgdata);
    assert(path);

    fp = fopen(path, "r");
    if (fp == NULL) {
        LOG_ERROR("can't open file to import");
        goto fail;
    }

    tok = json_tokener_new();
    if (tok == NULL) {
        LOG_ERROR("fail to create a json tokener");
        goto fail;
    }

    /* parse json file */
    while (fgets(str, MAX_LEN, fp) != NULL) {
        json_obj = json_tokener_parse_ex(tok, str, strlen(str));
        jerr = json_tokener_get_error(tok);
        if (jerr != json_tokener_continue)
            break;
    }
    if (jerr != json_tokener_success || !json_obj) {
        LOG_ERROR("json tokener fails");
        goto fail;
    }

    /* check the type of the object */
    if (!json_object_is_type(json_obj, json_type_object)) {
        LOG_ERROR("file format error");
        goto fail;
    }

    ret = json_object_object_get_ex(json_obj, "phrase", &array_obj);
    if (ret == 0) {
        LOG_ERROR("json file has no key named `phrase'");
        goto fail;
    }

    /* userphrase should be of type array */
    if (!json_object_is_type(array_obj, json_type_array)) {
        LOG_ERROR("file format error");
        goto fail;
    }

    array_length = json_object_array_length(array_obj);
    /* each phrase entry is stored in array_object */
    for (i = 0; i < array_length; ++i) {
        phrase_obj = json_object_array_get_idx(array_obj, i);

        ret = json_object_object_get_ex(phrase_obj, "length", &tmp_obj);
        if (ret == 0) {
            LOG_ERROR("file format error");
            goto fail;
        }

        /* get the phrase length */
        phrase_length = json_object_get_int(tmp_obj);
        if (phrase_length > MAX_PHRASE_LEN) {
            LOG_ERROR("phrase length > MAX_PHRASE_LEN");
            goto fail;
        } else if (phrase_length < 0) {
            LOG_ERROR("phrase length < 0");
            goto fail;
        }

        /* get the phrase */
        ret = json_object_object_get_ex(phrase_obj, "phrase", &tmp_obj);
        if (ret == 0) {
            LOG_ERROR("file format error");
            goto fail;
        }
        word_seq = json_object_get_string(tmp_obj);

        phone_buf = ALC(uint16_t, phrase_length + 1);
        if (!phone_buf) {
            goto fail;
        }

        /* get the phones */
        for (j = 0; j < phrase_length; ++j) {
            ret = json_object_object_get_ex(phrase_obj, phones[j],&tmp_obj);
            if (ret == 0) {
                LOG_ERROR("file format error");
                free(phone_buf);
                goto fail;
            }
            phone_buf[j] = json_object_get_int(tmp_obj);
        }

        ret = UserUpdatePhrase(pgdata, phone_buf, word_seq);
        if (ret == USER_UPDATE_FAIL) {
            LOG_ERROR("UserUpdatePhrase return USER_UPDATE_FAIL");
            goto fail;
        }

        free(phone_buf);
    }

    /* free the json object */
    json_object_put(json_obj);
    fclose(fp);
    return IMPORT_SUCCESS;

  fail:
    json_object_put(json_obj);
    fclose(fp);
    return IMPORT_FAIL;
}
