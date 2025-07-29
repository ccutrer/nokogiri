
#include <nokogiri.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>
#include <xmlsec/dl.h>
#include <xmlsec/errors.h>
#include <xmlsec/templates.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/xmltree.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif

#if (XMLSEC_VERSION_MAJOR > 1) || (XMLSEC_VERSION_MAJOR == 1 && (XMLSEC_VERSION_MINOR > 2 || (XMLSEC_VERSION_MINOR == 2 && XMLSEC_VERSION_SUBMINOR >= 20)))
# define HAS_ECDSA
#endif

VALUE cNokogiriXmlXmlsecSigningError = Qnil;
VALUE cNokogiriXmlXmlsecVerificationError = Qnil;
VALUE cNokogiriXmlXmlsecKeystoreError = Qnil;
VALUE cNokogiriXmlXmlsecEncryptionError = Qnil;
VALUE cNokogiriXmlXmlsecDecryptionError = Qnil;

#define ERROR_STACK_SIZE      4096
static char xmlsec_error_stack[ERROR_STACK_SIZE];
static int xmlsec_error_stack_pos;

static
char *
xmlsec_get_last_error(void)
{
  return xmlsec_error_stack;
}

static
int
xmlsec_has_last_error(void)
{
  return xmlsec_error_stack[0] != '\0';
}

static
void
store_error_callback(const char *file,
                     int line,
                     const char *func,
                     const char *errorObject,
                     const char *errorSubject,
                     int reason,
                     const char *msg)
{
  size_t i = 0;
  const char *error_msg = NULL;
  int amt = 0;
  if (xmlsec_error_stack_pos >= ERROR_STACK_SIZE) {
    // Just bail. Earlier errors are more interesting usually anyway.
    return;
  }

  for (i = 0; (i < XMLSEC_ERRORS_MAX_NUMBER) && (xmlSecErrorsGetMsg(i) != NULL); ++i) {
    if (xmlSecErrorsGetCode(i) == reason) {
      error_msg = xmlSecErrorsGetMsg(i);
      break;
    }
  }

  amt = snprintf(
          &xmlsec_error_stack[xmlsec_error_stack_pos],
          ERROR_STACK_SIZE - (size_t)xmlsec_error_stack_pos,
          "func=%s:file=%s:line=%d:obj=%s:subj=%s:error=%d:%s:%s\n",
          func, file, line, errorObject, errorSubject, reason,
          error_msg ? error_msg : "", msg);

  if (amt > 0) {
    xmlsec_error_stack_pos += amt;
  }
}

static
void
xmlsec_reset_last_error(void)
{
  xmlsec_error_stack[0] = '\0';
  xmlsec_error_stack_pos = 0;
  xmlSecErrorsSetCallback(store_error_callback);
}

static
xmlSecDSigCtxPtr
xmlsec_create_dsig_context(xmlSecKeysMngrPtr keysMngr)
{
  xmlSecDSigCtxPtr dsigCtx = xmlSecDSigCtxCreate(keysMngr);
  if (!dsigCtx) {
    return NULL;
  }

  // Restrict ReferenceUris to same document or empty to avoid XXE attacks.
  dsigCtx->enabledReferenceUris = xmlSecTransformUriTypeEmpty |
                                  xmlSecTransformUriTypeSameDocument;

  return dsigCtx;
}

static
xmlSecKeysMngrPtr
xmlsec_create_keys_mngr_with_single_key(
  VALUE rb_key,
  const char *key_name,
  VALUE* rb_exception_result_out,
  const char **exception_message_out)
{
  VALUE rb_exception_result = Qnil;
  const char *exception_message = NULL;
  xmlSecKeysMngrPtr keysMngr = NULL;
  xmlSecKeyPtr key = NULL;

  /* create and initialize keys manager, we use a simple list based
   * keys manager, implement your own xmlSecKeysStore klass if you need
   * something more sophisticated
   */
  keysMngr = xmlSecKeysMngrCreate();
  if (keysMngr == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecDecryptionError;
    exception_message = "failed to create keys manager.";
    goto done;
  }
  if (xmlSecCryptoAppDefaultKeysMngrInit(keysMngr) < 0) {
    rb_exception_result = cNokogiriXmlXmlsecDecryptionError;
    exception_message = "failed to initialize keys manager.";
    goto done;
  }

  /* load private RSA key */
  key = xmlSecCryptoAppKeyLoadMemory((const xmlSecByte *)RSTRING_PTR(rb_key),
                                     (size_t)RSTRING_LEN(rb_key),
                                     xmlSecKeyDataFormatPem,
                                     NULL, // the key file password
                                     NULL, // the key password callback
                                     NULL);// the user context for password callback
  if (key == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecDecryptionError;
    exception_message = "failed to load rsa key";
    goto done;
  }

  if (xmlSecKeySetName(key, (const xmlChar *) key_name) < 0) {
    rb_exception_result = cNokogiriXmlXmlsecDecryptionError;
    exception_message = "failed to set key name";
    goto done;
  }

  /* add key to keys manager, from now on keys manager is responsible
   * for destroying key
   */
  if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(keysMngr, key) < 0) {
    rb_exception_result = cNokogiriXmlXmlsecDecryptionError;
    exception_message = "failed to add key to keys manager";
    goto done;
  }

done:
  if (rb_exception_result != Qnil) {
    if (key) {
      xmlSecKeyDestroy(key);
    }

    if (keysMngr) {
      xmlSecKeysMngrDestroy(keysMngr);
      keysMngr = NULL;
    }
  }

  *rb_exception_result_out = rb_exception_result;
  *exception_message_out = exception_message;
  return keysMngr;
}

// Constructs a xmlSecKeysMngrPtr and adds all the certs included in |rb_certs|
// array as trusted certificates.
static
xmlSecKeysMngrPtr
xmlsec_create_keys_mngr_with_rb_certificate_array(
  VALUE rb_certs,
  VALUE* rb_exception_result_out,
  const char **exception_message_out)
{
  VALUE rb_exception_result = Qnil, rb_cert = Qnil;
  const char *exception_message = NULL, *cert = NULL;
  long numCerts = RARRAY_LEN(rb_certs);
  xmlSecKeysMngrPtr keysMngr = xmlSecKeysMngrCreate();
  long numSuccessful = 0;

  if (keysMngr == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecDecryptionError;
    exception_message = "failed to create keys manager.";
    goto done;
  }

  if (xmlSecCryptoAppDefaultKeysMngrInit(keysMngr) < 0) {
    rb_exception_result = cNokogiriXmlXmlsecKeystoreError;
    exception_message = "could not initialize key manager";
    goto done;
  }

  for (long i = 0; i < numCerts; i++) {
    rb_cert = RARRAY_PTR(rb_certs)[i];
    rb_cert = rb_obj_as_string(rb_cert);
    Check_Type(rb_cert, T_STRING);
    cert = RSTRING_PTR(rb_cert);

    if (xmlSecCryptoAppKeysMngrCertLoadMemory(keysMngr,
        (xmlSecByte *)cert,
        (size_t)RSTRING_LEN(rb_cert),
        xmlSecKeyDataFormatPem,
        xmlSecKeyDataTypeTrusted) < 0) {
      rb_warn("failed to load certificate at index %zu", i);
    } else {
      numSuccessful++;
    }
  }

  // note, numCerts could be zero, meaning that we should use system SSL certs
  if (numSuccessful == 0 && numCerts != 0) {
    rb_exception_result = cNokogiriXmlXmlsecKeystoreError;
    exception_message = "Could not load any of the specified certificates for signature verification";
    goto done;
  }

done:
  if (!NIL_P(rb_exception_result)) {
    if (keysMngr) {
      xmlSecKeysMngrDestroy(keysMngr);
      keysMngr = NULL;
    }
  }

  *rb_exception_result_out = rb_exception_result;
  *exception_message_out = exception_message;
  return keysMngr;
}

static int
add_ruby_key_to_manager(VALUE rb_key, VALUE rb_value, VALUE rb_key_manager)
{
  xmlSecKeysMngrPtr keysMngr = (xmlSecKeysMngrPtr)rb_key_manager;

  Check_Type(rb_key, T_STRING);
  Check_Type(rb_value, T_STRING);
  const char *key_name = StringValueCStr(rb_key);

  // load key
  xmlSecKeyPtr key = xmlSecCryptoAppKeyLoadMemory((xmlSecByte *)RSTRING_PTR(rb_value),
                     (size_t)RSTRING_LEN(rb_value),
                     xmlSecKeyDataFormatPem,
                     NULL, // password
                     NULL, NULL);
  if (key == NULL) {
    rb_warn("failed to load '%s' public or private pem key", key_name);
    return ST_CONTINUE;
  }

  // set key name
  if (xmlSecKeySetName(key, (const xmlChar *)key_name) < 0) {
    rb_warn("failed to set key name for key '%s'", key_name);
    return ST_CONTINUE;
  }

  // add key to key manager; from now on the manager is responsible for
  // destroying the key
  if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(keysMngr, key) < 0) {
    rb_warn("failed to add key '%s' to key manager", key_name);
    return ST_CONTINUE;
  }

  return ST_CONTINUE;
}

// Constructs a xmlSecKeysMngr and adds all the named to key mappings
// specified by the |rb_hash| to the key manager.
//
// Caller takes ownership. Free with xmlSecKeysMngrDestroy().
static
xmlSecKeysMngrPtr
xmlsec_create_keys_mngr_from_named_keys(
  VALUE rb_hash,
  VALUE* rb_exception_result_out,
  const char **exception_message_out)
{
  xmlSecKeysMngrPtr keysMngr = xmlSecKeysMngrCreate();
  if (keysMngr == NULL) { return NULL; }
  if (xmlSecCryptoAppDefaultKeysMngrInit(keysMngr) < 0) {
    *rb_exception_result_out = cNokogiriXmlXmlsecKeystoreError;
    *exception_message_out = "could not initialize key manager";
    xmlSecKeysMngrDestroy(keysMngr);
    return NULL;
  }

  rb_hash_foreach(rb_hash, add_ruby_key_to_manager, (VALUE)keysMngr);

  return keysMngr;
}

// Supported signature algorithms taken from #6 of
// http://www.w3.org/TR/xmldsig-core1/
static const char RSA_SHA1[] = "rsa-sha1";
static const char RSA_SHA224[] = "rsa-sha224";
static const char RSA_SHA256[] = "rsa-sha256";
static const char RSA_SHA384[] = "rsa-sha384";
static const char RSA_SHA512[] = "rsa-sha512";
static const char DSA_SHA1[] = "dsa-sha1";

#ifdef HAS_ECDSA
static const char ECDSA_SHA1[] = "ecdsa-sha1";
static const char ECDSA_SHA224[] = "ecdsa-sha224";
static const char ECDSA_SHA256[] = "ecdsa-sha256";
static const char ECDSA_SHA384[] = "ecdsa-sha384";
static const char ECDSA_SHA512[] = "ecdsa-sha512";
static const char DSA_SHA256[] = "dsa-sha256";
#endif  // HAS_ECDSA

static
xmlSecTransformId
xmlsec_get_signature_method(VALUE rb_signature_alg,
                            VALUE* rb_exception_result,
                            const char **exception_message)
{
  const char *signature_algorithm = RSTRING_PTR(rb_signature_alg);
  size_t signature_algorithm_len = (size_t)RSTRING_LEN(rb_signature_alg);

  if (strncmp(RSA_SHA1, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformRsaSha1Id;
  } else if (strncmp(RSA_SHA224, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformRsaSha224Id;
  } else if (strncmp(RSA_SHA256, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformRsaSha256Id;
  } else if (strncmp(RSA_SHA384, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformRsaSha384Id;
  } else if (strncmp(RSA_SHA512, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformRsaSha512Id;

  }
#ifdef HAS_ECDSA
  else if (strncmp(ECDSA_SHA1, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformEcdsaSha1Id;
  } else if (strncmp(ECDSA_SHA224, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformEcdsaSha224Id;
  } else if (strncmp(ECDSA_SHA256, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformEcdsaSha256Id;
  } else if (strncmp(ECDSA_SHA384, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformEcdsaSha384Id;
  } else if (strncmp(ECDSA_SHA512, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformEcdsaSha512Id;
  } else if (strncmp(DSA_SHA1, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformDsaSha1Id;
  } else if (strncmp(DSA_SHA256, signature_algorithm, signature_algorithm_len) == 0) {
    return xmlSecTransformDsaSha256Id;
  }
#endif  // HAS_ECDSA

  *rb_exception_result = rb_eArgError;
  *exception_message = "Unknown :signature_alg";
  return xmlSecTransformIdUnknown;
}

// Supported digest algorithms taken from #6 of
// http://www.w3.org/TR/xmldsig-core1/
static const char DIGEST_SHA1[] = "sha1";
static const char DIGEST_SHA224[] = "sha224";
static const char DIGEST_SHA256[] = "sha256";
static const char DIGEST_SHA384[] = "sha384";
static const char DIGEST_SHA512[] = "sha512";


static
xmlSecTransformId
xmlsec_get_digest_method(VALUE rb_digest_alg,
                         VALUE* rb_exception_result,
                         const char **exception_message)
{
  const char *digest_algorithm = RSTRING_PTR(rb_digest_alg);
  size_t digest_algorithm_len = (size_t)RSTRING_LEN(rb_digest_alg);

  if (strncmp(DIGEST_SHA1, digest_algorithm, digest_algorithm_len) == 0) {
    return xmlSecTransformSha1Id;
  } else if (strncmp(DIGEST_SHA224, digest_algorithm, digest_algorithm_len) == 0) {
    return xmlSecTransformSha224Id;
  } else if (strncmp(DIGEST_SHA256, digest_algorithm, digest_algorithm_len) == 0) {
    return xmlSecTransformSha256Id;
  } else if (strncmp(DIGEST_SHA384, digest_algorithm, digest_algorithm_len) == 0) {
    return xmlSecTransformSha384Id;
  } else if (strncmp(DIGEST_SHA512, digest_algorithm, digest_algorithm_len) == 0) {
    return xmlSecTransformSha512Id;
  }

  *rb_exception_result = rb_eArgError;
  *exception_message = "Unknown :digest_algorithm";
  return xmlSecTransformIdUnknown;
}

// Canonicalization algorithms
// http://www.w3.org/TR/xmldsig-core1/#sec-Canonicalization
static const char C14N[] = "c14n";
static const char C14N_WITH_COMMENTS[] = "c14n-with-comments";
static const char EXCL_C14N[] = "exc-c14n";
static const char EXCL_C14N_WITH_COMMENTS[] = "exc-c14n-with-comments";

static
xmlSecTransformId
xmlsec_get_canonicalization_method(VALUE rb_canon_alg,
                                   VALUE *rb_exception_result,
                                   const char **exception_message)
{
  const char *canonicalization_algorithm = RSTRING_PTR(rb_canon_alg);
  size_t canonicalization_algorithm_len = (size_t)RSTRING_LEN(rb_canon_alg);

  if (strncmp(C14N, canonicalization_algorithm, canonicalization_algorithm_len) == 0) {
    return xmlSecTransformInclC14NId;
  } else if (strncmp(C14N_WITH_COMMENTS, canonicalization_algorithm, canonicalization_algorithm_len) == 0) {
    return xmlSecTransformInclC14NWithCommentsId;
  } else if (strncmp(EXCL_C14N, canonicalization_algorithm, canonicalization_algorithm_len) == 0) {
    return xmlSecTransformExclC14NId;
  } else if (strncmp(EXCL_C14N_WITH_COMMENTS, canonicalization_algorithm, canonicalization_algorithm_len) == 0) {
    return xmlSecTransformExclC14NWithCommentsId;
  }

  *rb_exception_result = rb_eArgError;
  *exception_message = "Unknown :canon_alg";
  return xmlSecTransformIdUnknown;
}

// Block Encryption Strings
static const char TRIPLEDES_CBC[] = "tripledes-cbc";
static const char AES128_CBC[] = "aes128-cbc";
static const char AES256_CBC[] = "aes256-cbc";
static const char AES192_CBC[] = "aes192-cbc";

static
xmlSecTransformId
xmlsec_get_block_encryption_method(VALUE rb_block_encryption_alg,
                                   VALUE *rb_exception_result,
                                   const char **exception_message,
                                   const char **key_type,
                                   size_t *key_bits)
{
  const char *block_encryption_algorithm = RSTRING_PTR(rb_block_encryption_alg);
  size_t block_encryption_algorithm_len = (size_t)RSTRING_LEN(rb_block_encryption_alg);

  if (strncmp(AES256_CBC, block_encryption_algorithm, block_encryption_algorithm_len) == 0) {
    *key_type = "aes";
    *key_bits = 256;
    return xmlSecTransformAes256CbcId;
  } else if (strncmp(AES128_CBC, block_encryption_algorithm, block_encryption_algorithm_len) == 0) {
    *key_type = "aes";
    *key_bits = 128;
    return xmlSecTransformAes128CbcId;
  } else if (strncmp(AES192_CBC, block_encryption_algorithm, block_encryption_algorithm_len) == 0) {
    *key_type = "aes";
    *key_bits = 192;
    return xmlSecTransformAes192CbcId;
  } else if (strncmp(TRIPLEDES_CBC, block_encryption_algorithm, block_encryption_algorithm_len) == 0) {
    *key_type = "des";
    *key_bits = 192;
    return xmlSecTransformDes3CbcId;
  } else {
    *rb_exception_result = rb_eArgError;
    *exception_message = "Unknown :block_encryption";
  }

  return xmlSecTransformIdUnknown;
}

// Key Transport Strings
static const char RSA1_5[] = "rsa-1_5";
static const char RSA_OAEP_MGF1P[] = "rsa-oaep-mgf1p";

static
xmlSecTransformId
xmlsec_get_key_transport_method(VALUE rb_key_transport_alg,
                                VALUE *rb_exception_result,
                                const char **exception_message)
{
  const char *key_transport_value = RSTRING_PTR(rb_key_transport_alg);
  size_t key_transport_len = (size_t)RSTRING_LEN(rb_key_transport_alg);

  if (strncmp(RSA1_5, key_transport_value, key_transport_len) == 0) {
    return xmlSecTransformRsaPkcs1Id;
  } else if (strncmp(RSA_OAEP_MGF1P, key_transport_value, key_transport_len) == 0) {
    return xmlSecTransformRsaOaepId;
  } else {
    *rb_exception_result = rb_eArgError;
    *exception_message = "Unknown :key_transport value";
  }

  return xmlSecTransformIdUnknown;
}

VALUE
noko_xml_node__decrypt(int argc, VALUE *argv, VALUE self)
{
  VALUE rb_exception_result = Qnil, rb_kwargs, rb_key, rb_key_name;
  const char *exception_message = NULL, *key_name = NULL;
  xmlNodePtr node = NULL, previous_sibling = NULL, parent = NULL;
  xmlSecEncCtxPtr encCtx = NULL;
  xmlSecKeysMngrPtr keysMngr = NULL;

  rb_scan_args(argc, argv, "0:", &rb_kwargs);
  if (NIL_P(rb_kwargs)) {
    rb_kwargs = rb_hash_new();
  }

  ID keywords[] = {
    // Required
    rb_intern_const("key"),
    // Optional
    rb_intern_const("key_name"),
  };
  VALUE values[sizeof keywords / sizeof keywords[0]];

  rb_get_kwargs(rb_kwargs, keywords, 1, 1, values);

  rb_key = values[0];
  rb_key_name = values[1];
  Check_Type(rb_key, T_STRING);
  if (!RB_NIL_OR_UNDEF_P(rb_key_name)) {
    Check_Type(rb_key_name, T_STRING);
    key_name = StringValueCStr(rb_key_name);
  }
  Noko_Node_Get_Struct(self, xmlNode, node);

  xmlsec_reset_last_error();

  previous_sibling = xmlPreviousElementSibling(node);
  parent = node->parent;

  keysMngr = xmlsec_create_keys_mngr_with_single_key(rb_key,
             key_name,
             &rb_exception_result,
             &exception_message);
  if (keysMngr == NULL) {
    // Propagate the exception.
    goto done;
  }

  // create encryption context
  encCtx = xmlSecEncCtxCreate(keysMngr);
  if (encCtx == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecDecryptionError;
    exception_message = "failed to create encryption context";
    goto done;
  }
  // don't let xmlsec free the node we're looking at out from under us
  encCtx->flags |= XMLSEC_ENC_RETURN_REPLACED_NODE;

#ifdef XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH
  // Enable lax key search, since xmlsec 1.3.0
  encCtx->keyInfoReadCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
#endif

  // decrypt the data
  if ((xmlSecEncCtxDecrypt(encCtx, node) < 0) || (encCtx->result == NULL)) {
    rb_exception_result = cNokogiriXmlXmlsecDecryptionError;
    exception_message = "decryption failed";
    goto done;
  }

  if (encCtx->resultReplaced == 0) {
    rb_exception_result = cNokogiriXmlXmlsecDecryptionError;
    exception_message =  "Not implemented: don't know how to handle decrypted, non-XML data yet";
    goto done;
  }

done:
  // cleanup
  if (encCtx != NULL) {
    // the replaced node is orphaned, but not freed; let Nokogiri
    // own it now
    if (encCtx->replacedNodeList != NULL) {
      noko_xml_document_pin_node(encCtx->replacedNodeList);
      // no really, please don't free it
      encCtx->replacedNodeList = NULL;
    }
    xmlSecEncCtxDestroy(encCtx);
  }

  if (keysMngr != NULL) {
    xmlSecKeysMngrDestroy(keysMngr);
  }

  xmlSecErrorsSetCallback(xmlSecErrorsDefaultCallback);

  if (rb_exception_result != Qnil) {
    if (xmlsec_has_last_error()) {
      rb_raise(rb_exception_result, "%s, XmlSec error: %s", exception_message,
               xmlsec_get_last_error());
    } else {
      rb_raise(rb_exception_result, "%s", exception_message);
    }
  }

  if (previous_sibling != NULL) {
    node = xmlNextElementSibling(previous_sibling);
    if (!node) {
      return Qnil;
    }
    return noko_xml_node_wrap(Qnil, node);
  } else {
    node = xmlFirstElementChild(parent);
    if (!node) {
      return Qnil;
    }
    return noko_xml_node_wrap(Qnil, node);
  }
}

VALUE
noko_xml_node__encrypt(int argc, VALUE *argv, VALUE self)
{
  VALUE rb_exception_result = Qnil, rb_kwargs, rb_key, rb_block_encryption, rb_key_transport, rb_certificate, rb_key_name;
  const char *exception_message = NULL, *key_name = NULL, *certificate = NULL, *key_type = NULL;
  size_t key_bits = 0;
  xmlDocPtr doc = NULL;
  xmlNodePtr node = NULL;
  xmlNodePtr encryptedData_node = NULL;
  xmlNodePtr encryptedKey_node  = NULL;
  xmlNodePtr keyInfo_node = NULL;
  xmlSecEncCtxPtr encCtx = NULL;
  xmlSecKeysMngrPtr keysMngr = NULL;
  xmlSecTransformId block_encryption, key_transport;

  xmlsec_reset_last_error();

  rb_scan_args(argc, argv, "0:", &rb_kwargs);
  if (NIL_P(rb_kwargs)) {
    rb_kwargs = rb_hash_new();
  }

  ID keywords[] = {
    rb_intern_const("key"),
    rb_intern_const("block_encryption"),
    rb_intern_const("key_transport"),
    rb_intern_const("certificate"),
    rb_intern_const("key_name"),
  };
  VALUE values[sizeof keywords / sizeof keywords[0]];

  rb_get_kwargs(rb_kwargs, keywords, 3, 2, values);

  rb_key = values[0];
  rb_block_encryption = values[1];
  rb_certificate = values[3];
  rb_key_name = values[4];
  rb_key_transport = values[2];

  Check_Type(rb_key, T_STRING);
  if (!RB_NIL_OR_UNDEF_P(rb_certificate)) {
    Check_Type(rb_certificate, T_STRING);
    certificate = RSTRING_PTR(rb_certificate);
  }
  Check_Type(rb_block_encryption, T_STRING);
  if (!RB_NIL_OR_UNDEF_P(rb_key_name)) {
    Check_Type(rb_key_name, T_STRING);
    key_name = StringValueCStr(rb_key_name);
  }
  Check_Type(rb_key_transport, T_STRING);

  block_encryption = xmlsec_get_block_encryption_method(rb_block_encryption,
                     &rb_exception_result,
                     &exception_message,
                     &key_type, &key_bits);
  if (block_encryption == xmlSecTransformIdUnknown) {
    goto done;
  }

  // From :key_transport
  key_transport = xmlsec_get_key_transport_method(rb_key_transport,
                  &rb_exception_result,
                  &exception_message);
  if (key_transport == xmlSecTransformIdUnknown) {
    goto done;
  }

  Noko_Node_Get_Struct(self, xmlNode, node);
  doc = node->doc;

  // create encryption template to encrypt XML file and replace
  // its content with encryption result
  encryptedData_node = xmlSecTmplEncDataCreate(doc, block_encryption, NULL,
                       xmlSecTypeEncElement, NULL, NULL);
  if (encryptedData_node == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
    exception_message = "failed to create encryption template";
    goto done;
  }

  // we want to put encrypted data in the <enc:CipherValue/> node
  if (xmlSecTmplEncDataEnsureCipherValue(encryptedData_node) == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
    exception_message = "failed to add CipherValue node";
    goto done;
  }

  // add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the
  // signed document
  keyInfo_node = xmlSecTmplEncDataEnsureKeyInfo(encryptedData_node, NULL);
  if (keyInfo_node == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
    exception_message = "failed to add key info";
    goto done;
  }

  if (certificate) {
    // add <dsig:X509Data/>
    if (xmlSecTmplKeyInfoAddX509Data(keyInfo_node) == NULL) {
      rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
      exception_message = "failed to add X509Data node";
      goto done;
    }
  }

  if (key_name != NULL) {
    if (xmlSecTmplKeyInfoAddKeyName(keyInfo_node, NULL) == NULL) {
      rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
      exception_message = "failed to add key name";
      goto done;
    }
  }

  if ((keysMngr = xmlsec_create_keys_mngr_with_single_key(
                    rb_key, key_name,
                    &rb_exception_result,
                    &exception_message)) == NULL) {
    // Propagate the exception.
    goto done;
  }

  // create encryption context, we don't need keys manager in this example
  encCtx = xmlSecEncCtxCreate(keysMngr);
  if (encCtx == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
    exception_message = "failed to create encryption context";
    goto done;
  }

#ifdef XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH
  // Enable lax key search, since xmlsec 1.3.0
  encCtx->keyInfoWriteCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
#endif

  // Generate the symmetric key.
  encCtx->encKey = xmlSecKeyGenerateByName(BAD_CAST key_type, key_bits,
                   xmlSecKeyDataTypeSession);

  if (encCtx->encKey == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
    exception_message = "failed to generate session key";
    goto done;
  }

  if (certificate) {
    // load certificate and add to the key
    if (xmlSecCryptoAppKeyCertLoadMemory(encCtx->encKey,
                                         (xmlSecByte *)certificate,
                                         (size_t)RSTRING_LEN(rb_certificate),
                                         xmlSecKeyDataFormatPem) < 0) {
      rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
      exception_message = "failed to load certificate";
      goto done;
    }
  }

  // Set key name.
  if (key_name) {
    if (xmlSecKeySetName(encCtx->encKey, (xmlSecByte *)key_name) < 0) {
      rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
      exception_message = "failed to set key name";
      goto done;
    }
  }

  // Add <enc:EncryptedKey/> node to the <dsig:KeyInfo/> tag to include
  // the session key.
  encryptedKey_node = xmlSecTmplKeyInfoAddEncryptedKey(keyInfo_node,
                      key_transport, // encMethodId encryptionMethod
                      NULL, // xmlChar *idAttribute
                      NULL, // xmlChar *typeAttribute
                      NULL  // xmlChar *recipient
                                                      );
  if (encryptedKey_node == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
    exception_message = "failed to add encrypted key node";
    goto done;
  }
  if (xmlSecTmplEncDataEnsureCipherValue(encryptedKey_node) == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
    exception_message = "failed to add encrypted cipher value";
    goto done;
  }

  // encrypt the data
  if (xmlSecEncCtxXmlEncrypt(encCtx, encryptedData_node, node) < 0) {
    rb_exception_result = cNokogiriXmlXmlsecEncryptionError;
    exception_message = "encryption failed";
    goto done;
  }

  // the template is inserted in the doc, so don't free it
  encryptedData_node = NULL;
  encryptedKey_node = NULL;

done:

  /* cleanup */
  if (encCtx != NULL) {
    xmlSecEncCtxDestroy(encCtx);
  }

  if (encryptedKey_node != NULL) {
    xmlFreeNode(encryptedKey_node);
  }

  if (encryptedData_node != NULL) {
    xmlFreeNode(encryptedData_node);
  }

  if (keysMngr != NULL) {
    xmlSecKeysMngrDestroy(keysMngr);
  }

  xmlSecErrorsSetCallback(xmlSecErrorsDefaultCallback);

  if (rb_exception_result != Qnil) {
    if (xmlsec_has_last_error()) {
      rb_raise(rb_exception_result, "%s, XmlSec error: %s", exception_message,
               xmlsec_get_last_error());
    } else {
      rb_raise(rb_exception_result, "%s", exception_message);
    }
  }

  return Qnil;
}

VALUE
noko_xml_node__sign(int argc, VALUE *argv, VALUE self)
{
  VALUE rb_exception_result = Qnil,
        rb_kwargs,
        rb_references = Qnil,
        rb_pre_digest_buffer_sym,
        rb_reference,
        rb_pre_digest_buffer,
        rb_rsa_key,
        rb_signature_alg,
        rb_digest_alg,
        rb_cert,
        rb_canon_alg,
        rb_uri,
        rb_key_name,
        rb_store_references;
  const char *exception_message = NULL, *key_name = NULL, *certificate = NULL, *ref_uri = NULL;
  xmlDocPtr doc = NULL;
  xmlNodePtr envelopeNode = NULL;
  xmlNodePtr signNode = NULL;
  xmlNodePtr refNode = NULL;
  xmlNodePtr keyInfo_node = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;
  int store_references = 0;
  xmlSecSize pos;
  xmlSecTransformId canon_algorithm, signature_algorithm, digest_algorithm;

  xmlsec_reset_last_error();

  rb_scan_args(argc, argv, "0:", &rb_kwargs);
  if (NIL_P(rb_kwargs)) {
    rb_kwargs = rb_hash_new();
  }

  ID keywords[] = {
    rb_intern_const("key"),
    rb_intern_const("signature_algorithm"),
    rb_intern_const("digest_algorithm"),
    rb_intern_const("certificate"),
    rb_intern_const("canonicalization_algorithm"),
    rb_intern_const("uri"),
    rb_intern_const("key_name"),
    rb_intern_const("store_references"),
  };
  VALUE values[sizeof keywords / sizeof keywords[0]];

  rb_get_kwargs(rb_kwargs, keywords, 3, 5, values);

  rb_rsa_key = values[0];
  rb_signature_alg = values[1];
  rb_digest_alg = values[2];
  rb_cert = values[3];
  rb_canon_alg = values[4];
  rb_uri = values[5];
  rb_key_name = values[6];
  rb_store_references = values[7];

  Check_Type(rb_rsa_key, T_STRING);
  Check_Type(rb_signature_alg, T_STRING);
  Check_Type(rb_digest_alg, T_STRING);

  if (!RB_NIL_OR_UNDEF_P(rb_cert)) {
    Check_Type(rb_cert, T_STRING);
    certificate = RSTRING_PTR(rb_cert);
  }
  if (!RB_NIL_OR_UNDEF_P(rb_key_name))  {
    Check_Type(rb_key_name, T_STRING);
    key_name = StringValueCStr(rb_key_name);
  }
  if (!RB_NIL_OR_UNDEF_P(rb_uri)) {
    Check_Type(rb_uri, T_STRING);
    ref_uri = StringValueCStr(rb_uri);
  }
  if (!RB_NIL_OR_UNDEF_P(rb_canon_alg)) {
    Check_Type(rb_canon_alg, T_STRING);
  }
  switch (TYPE(rb_store_references)) {
    case T_TRUE:
      store_references = 1;
      break;
    case T_FALSE:
    case T_NIL:
    case T_UNDEF:
      break;
    default:
      Check_Type(rb_store_references, T_TRUE);
      break;
  }

  canon_algorithm = xmlSecTransformExclC14NId; // default
  if (!RB_NIL_OR_UNDEF_P(rb_canon_alg)) {
    canon_algorithm = xmlsec_get_canonicalization_method(rb_canon_alg,
                      &rb_exception_result, &exception_message);
    if (canon_algorithm == xmlSecTransformIdUnknown) {
      goto done;
    }
  }

  signature_algorithm = xmlsec_get_signature_method(rb_signature_alg,
                        &rb_exception_result, &exception_message);
  if (signature_algorithm == xmlSecTransformIdUnknown) {
    // Propagate exception.
    goto done;
  }

  Noko_Node_Get_Struct(self, xmlNode, envelopeNode);
  doc = envelopeNode->doc;
  // create signature template for enveloped signature.
  signNode = xmlSecTmplSignatureCreate(doc, canon_algorithm,
                                       signature_algorithm, NULL);
  if (signNode == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecSigningError;
    exception_message = "failed to create signature template";
    goto done;
  }

  // add <dsig:Signature/> node to the doc
  xmlAddChild(envelopeNode, signNode);

  // add reference
  digest_algorithm = xmlsec_get_digest_method(rb_digest_alg,
                     &rb_exception_result, &exception_message);
  if (digest_algorithm == xmlSecTransformIdUnknown) {
    // Propagate exception.
    goto done;
  }

  refNode = xmlSecTmplSignatureAddReference(signNode, digest_algorithm,
            NULL, (const xmlChar *)ref_uri, NULL);
  if (refNode == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecSigningError;
    exception_message = "failed to add reference to signature template";
    goto done;
  }

  // add enveloped transform
  if (xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecSigningError;
    exception_message = "failed to add enveloped transform to reference";
    goto done;
  }

  if (xmlSecTmplReferenceAddTransform(refNode, canon_algorithm) == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecSigningError;
    exception_message = "failed to add canonicalization transform to reference";
    goto done;
  }

  // add <dsig:KeyInfo/>
  keyInfo_node = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
  if (keyInfo_node == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecSigningError;
    exception_message = "failed to add key info";
    goto done;
  }

  if (certificate) {
    // add <dsig:X509Data/>
    if (xmlSecTmplKeyInfoAddX509Data(keyInfo_node) == NULL) {
      rb_exception_result = cNokogiriXmlXmlsecSigningError;
      exception_message = "failed to add X509Data node";
      goto done;
    }
  }

  if (key_name) {
    // add <dsig:KeyName/>
    if (xmlSecTmplKeyInfoAddKeyName(keyInfo_node, NULL) == NULL) {
      rb_exception_result = cNokogiriXmlXmlsecSigningError;
      exception_message = "failed to add key name";
      goto done;
    }
  }

  // create signature context, we don't need keys manager in this example
  dsigCtx = xmlsec_create_dsig_context(NULL);
  if (dsigCtx == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecSigningError;
    exception_message = "failed to create signature context";
    goto done;
  }
  if (store_references) {
    dsigCtx->flags |= XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES |
                      XMLSEC_DSIG_FLAGS_STORE_MANIFEST_REFERENCES;
  }

  // load private key, assuming that there is not password
  dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory((xmlSecByte *)RSTRING_PTR(rb_rsa_key),
                     (size_t)RSTRING_LEN(rb_rsa_key),
                     xmlSecKeyDataFormatPem,
                     NULL, // password
                     NULL,
                     NULL);
  if (dsigCtx->signKey == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecSigningError;
    exception_message = "failed to load private key";
    goto done;
  }

  if (key_name) {
    // set key name
    if (xmlSecKeySetName(dsigCtx->signKey, (xmlSecByte *)key_name) < 0) {
      rb_exception_result = cNokogiriXmlXmlsecSigningError;
      exception_message = "failed to set key name";
      goto done;
    }
  }

  if (certificate) {
    // load certificate and add to the key
    if (xmlSecCryptoAppKeyCertLoadMemory(dsigCtx->signKey,
                                         (xmlSecByte *)certificate,
                                         (size_t)RSTRING_LEN(rb_cert),
                                         xmlSecKeyDataFormatPem) < 0) {
      rb_exception_result = cNokogiriXmlXmlsecSigningError;
      exception_message = "failed to load certificate";
      goto done;
    }
  }

  // sign the template
  if (xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
    rb_exception_result = cNokogiriXmlXmlsecSigningError;
    exception_message = "signature failed";
    goto done;
  }
  if (store_references) {
    rb_pre_digest_buffer_sym = ID2SYM(rb_intern("pre_digest_buffer"));
    rb_references = rb_ary_new2((long)xmlSecPtrListGetSize(&dsigCtx->signedInfoReferences));

    for (pos = 0; pos < xmlSecPtrListGetSize(&dsigCtx->signedInfoReferences); ++pos) {
      rb_reference = rb_hash_new();
      rb_ary_push(rb_references, rb_reference);
      xmlSecDSigReferenceCtxPtr dsigRefCtx = (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(&dsigCtx->signedInfoReferences,
                                             pos);
      xmlSecBufferPtr pre_digest_buffer = xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx);
      if (pre_digest_buffer && xmlSecBufferGetData(pre_digest_buffer)) {
        rb_pre_digest_buffer = rb_str_new((const char *)xmlSecBufferGetData(pre_digest_buffer),
                                          (long)xmlSecBufferGetSize(pre_digest_buffer));
        rb_hash_aset(rb_reference, rb_pre_digest_buffer_sym, rb_pre_digest_buffer);
      }
    }
  }

done:
  if (dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }

  xmlSecErrorsSetCallback(xmlSecErrorsDefaultCallback);

  if (rb_exception_result != Qnil) {
    // remove the signature node before raising an exception, so that
    // the document is untouched
    if (signNode != NULL) {
      xmlUnlinkNode(signNode);
      xmlFreeNode(signNode);
    }

    if (xmlsec_has_last_error()) {
      rb_raise(rb_exception_result, "%s, XmlSec error: %s", exception_message,
               xmlsec_get_last_error());
    } else {
      rb_raise(rb_exception_result, "%s", exception_message);
    }
  }

  if (store_references) {
    return rb_references;
  }
  return self;
}

VALUE
noko_xml_node__verify_signature(int argc, VALUE *argv, VALUE self)
{
  VALUE rb_exception_result = Qnil, rb_kwargs, rb_certs, rb_cert, rb_rsa_key, rb_verification_time,
        rb_verification_depth, rb_verify_certificates, rb_result, rb_keys;
  const char *exception_message = NULL, *rsa_key = NULL;
  xmlNodePtr node = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;
  xmlSecKeysMngrPtr keysMngr = NULL;

  xmlsec_reset_last_error();

  Noko_Node_Get_Struct(self, xmlNode, node);

  // verify start node
  if (!xmlSecCheckNodeName(node, xmlSecNodeSignature, xmlSecDSigNs)) {
    rb_exception_result = cNokogiriXmlXmlsecVerificationError;
    exception_message = "Can only verify a Signature node";
    goto done;
  }

  rb_scan_args(argc, argv, "01:", &rb_keys, &rb_kwargs);
  if (NIL_P(rb_kwargs)) {
    rb_kwargs = rb_hash_new();
  }

  ID keywords[] = {
    rb_intern_const("key"),
    rb_intern_const("certificates"),
    rb_intern_const("certificate"),
    rb_intern_const("verification_depth"),
    rb_intern_const("verification_time"),
    rb_intern_const("verify_certificates"),
  };
  VALUE values[sizeof keywords / sizeof keywords[0]];

  rb_get_kwargs(rb_kwargs, keywords, 0, 6, values);

  rb_certs = values[1];
  if (RB_NIL_OR_UNDEF_P(rb_certs)) {
    rb_certs = values[2];
  }

  rb_verification_depth = values[3];
  rb_verification_time = values[4];
  rb_verify_certificates = values[5];

  if (!RB_NIL_OR_UNDEF_P(rb_certs)) {
    if (TYPE(rb_certs) != T_ARRAY) {
      rb_cert = rb_certs;
      rb_certs = rb_ary_new();
      rb_ary_push(rb_certs, rb_cert);
    }

    keysMngr = xmlsec_create_keys_mngr_with_rb_certificate_array(rb_certs, &rb_exception_result,
               &exception_message);
    if (keysMngr == NULL) {
      goto done;
    }
  } else if (!RB_NIL_OR_UNDEF_P(rb_rsa_key = values[0])) {
    Check_Type(rb_rsa_key,  T_STRING);
    rsa_key = RSTRING_PTR(rb_rsa_key);
  } else {
    Check_Type(rb_keys, T_HASH);
    keysMngr = xmlsec_create_keys_mngr_from_named_keys(rb_keys, &rb_exception_result,
               &exception_message);
    if (keysMngr == NULL) {
      goto done;
    }
  }

  // Create signature context.
  dsigCtx = xmlsec_create_dsig_context(keysMngr);
  if (dsigCtx == NULL) {
    rb_exception_result = cNokogiriXmlXmlsecVerificationError;
    exception_message = "failed to create signature context";
    goto done;
  }

  if (!RB_NIL_OR_UNDEF_P(rb_verification_time)) {
    rb_verification_time = rb_Integer(rb_verification_time);
    dsigCtx->keyInfoReadCtx.certsVerificationTime = (time_t)NUM2LONG(rb_verification_time);
  }

  if (rb_verify_certificates == Qfalse) {
    dsigCtx->keyInfoReadCtx.flags |= XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;
  }

  if (!RB_NIL_OR_UNDEF_P(rb_verification_depth)) {
    rb_verification_depth = rb_Integer(rb_verification_depth);
    dsigCtx->keyInfoReadCtx.certsVerificationDepth = NUM2INT(rb_verification_depth);
  }

  if (rsa_key) {
    // load public key
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory((xmlSecByte *)rsa_key,
                       (size_t)RSTRING_LEN(rb_rsa_key),
                       xmlSecKeyDataFormatPem,
                       NULL, // password
                       NULL, NULL);
    if (dsigCtx->signKey == NULL) {
      rb_exception_result = cNokogiriXmlXmlsecVerificationError;
      exception_message = "failed to load public pem key";
      goto done;
    }
  }

  // verify signature
  if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
    rb_exception_result = cNokogiriXmlXmlsecVerificationError;
    exception_message = "error occurred during signature verification";
    goto done;
  }

  if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
    rb_result = Qtrue;
  }

done:
  if (dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }

  if (keysMngr != NULL) {
    xmlSecKeysMngrDestroy(keysMngr);
  }

  xmlSecErrorsSetCallback(xmlSecErrorsDefaultCallback);

  if (!NIL_P(rb_exception_result)) {
    if (xmlsec_has_last_error()) {
      rb_raise(rb_exception_result, "%s, XmlSec error: %s", exception_message,
               xmlsec_get_last_error());
    } else {
      rb_raise(rb_exception_result, "%s", exception_message);
    }
  }

  return rb_result;
}

// Initialize xmlsec
void
noko_init_xmlsec(void)
{
#ifndef XMLSEC_NO_XSLT
  xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

#ifndef XMLSEC_NO_XSLT
  xmlIndentTreeOutput = 1;

  /* Disable all XSLT options that give filesystem and network access. */
  xsltSecPrefs = xsltNewSecurityPrefs();
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
  xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

// xmlsec overwrites the default external entity loader unless you're running
// xmlsec 1.3.6 or later _and_ libxml2 2.13.0 or later.
// we don't need to do that because all of the defaults in ParseOptions have nonet included
#if LIBXML_VERSION < 21300 || XMLSEC_VERSION_MINOR < 3 || XMLSEC_VERSION_SUBMINOR < 6
  xmlExternalEntityLoader currentExternalEntityLoader = xmlGetExternalEntityLoader();
#endif

  if (xmlSecInit() < 0) {
    rb_raise(rb_eRuntimeError, "xmlsec initialization failed");
    return;
  }
#if LIBXML_VERSION < 21300 || XMLSEC_VERSION_MINOR < 3 || XMLSEC_VERSION_SUBMINOR < 6
  xmlSetExternalEntityLoader(currentExternalEntityLoader);
#endif
  if (xmlSecCheckVersion() != 1) {
    rb_raise(rb_eRuntimeError, "xmlsec version is not compatible");
    return;
  }
  // xmlsec doesn't have a convenient way to directly get the loaded version.
  // xmlSecCheckVersion just says "compatible", meaning the loaded version is
  // newer than the compiled version. so do some iterations check "exact" versions
  // to find the loaded version. The common case is we're using the same version
  // we compiled against, so this will break on after the first iterator.
  xmlSecErrorsDefaultCallbackEnableOutput(1);
  int major = XMLSEC_VERSION_MAJOR;
  int minor = XMLSEC_VERSION_MINOR;
  int subminor = XMLSEC_VERSION_SUBMINOR;
  bool found = false;
  while (minor < 100) {
    while (subminor < 100) {
      if (xmlSecCheckVersionExt(major, minor, subminor, xmlSecCheckVersionExactMatch) == 1) {
        found = true;
        break;
      }
      subminor++;
    }
    if (found) {
      break;
    }
    minor++;
    subminor = 0;
  }
  xmlSecErrorsDefaultCallbackEnableOutput(0);
  rb_const_set(mNokogiri, rb_intern("XMLSEC_LOADED_VERSION"), found ? rb_sprintf("%d.%d.%d", major, minor,
               subminor) : NOKOGIRI_STR_NEW("0.0.0", 5));

  // load crypto library if necessary
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
  if (xmlSecCryptoDLLoadLibrary(NULL) < 0) {
    rb_raise(rb_eRuntimeError,
             "Error: unable to load default xmlsec-crypto library. Make sure"
             "that you have it installed and check shared libraries path\n"
             "(LD_LIBRARY_PATH) environment variable.\n");
    return;
  }
#endif

  if (xmlSecCryptoAppInit(NULL) < 0) {
    rb_raise(rb_eRuntimeError, "unable to initialize crypto engine");
    return;
  }
  if (xmlSecCryptoInit() < 0) {
    rb_raise(rb_eRuntimeError, "xmlsec-crypto initialization failed");
  }

  // Set up Ruby classes and methods for XMLSec
  VALUE mNokogiriXmlXMLSec = rb_define_module_under(mNokogiriXml, "XMLSec");

  cNokogiriXmlXmlsecDecryptionError   = rb_define_class_under(mNokogiriXmlXMLSec, "DecryptionError",   rb_eRuntimeError);
  cNokogiriXmlXmlsecEncryptionError   = rb_define_class_under(mNokogiriXmlXMLSec, "EncryptionError",   rb_eRuntimeError);
  cNokogiriXmlXmlsecKeystoreError     = rb_define_class_under(mNokogiriXmlXMLSec, "KeystoreError",     rb_eRuntimeError);
  cNokogiriXmlXmlsecSigningError      = rb_define_class_under(mNokogiriXmlXMLSec, "SigningError",      rb_eRuntimeError);
  cNokogiriXmlXmlsecVerificationError = rb_define_class_under(mNokogiriXmlXMLSec, "VerificationError", rb_eRuntimeError);

  rb_define_method(cNokogiriXmlNode, "decrypt", noko_xml_node__decrypt, -1);
  rb_define_method(cNokogiriXmlNode, "encrypt", noko_xml_node__encrypt, -1);
  rb_define_method(cNokogiriXmlNode, "sign", noko_xml_node__sign, -1);
  rb_define_method(cNokogiriXmlNode, "verify_signature", noko_xml_node__verify_signature, -1);
}
