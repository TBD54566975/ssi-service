
### Key Management

The service can store keys that are used to digitally sign credentials (and other data). All such keys are encrypted at
the application before being stored using a MasterKey (a.k.a. a Key Encryption Key or KEK). The MasterKey can be
generated automatically during boot time, or we can use the MasterKey housed in an external Key
Management System (KMS) like GCP KMS or AWS KMS.

For production deployments, using external KMS is strongly recommended.

To use an external KMS:

1. Create a symmetric encryption key in your KMS. You MUST select the algorithm that uses AES-256 block cipher in
   Galois/Counter Mode (GCM). At the time of writing, this is the only algorithm supported by AWS and GCP for symmetric encrypt/decrypt.
   In GCP, the algorithm will be called "Google symmetric key." It will be preselected and grayed out.
2. Set the `master_key_uri` field of the `[services.keystore]` section using the format described
   in [tink](https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#key-management-systems)
   (we use the tink library under the hood).
3. Set the `kms_credentials_path` field of the `[services.keystore]` section to point to your credentials file,
   according
   to [this section](https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#credentials).
4. Win!

To use a randomly generated encryption key (NOT RECOMMENDED FOR ANY PRODUCTION ENVIRONMENT):

1. Make sure that `master_key_uri` and `kms_credentials_path` of the `[services.keystore]` section are not set.

Note that at this time, we do not currently support rotating the master key.