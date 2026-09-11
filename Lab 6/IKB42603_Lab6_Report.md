# IKB42603 Cloud Computing Security Essentials
## Lab 6: Object Storage Security and the Data Security Lifecycle

**Name:** Muhammad Aqeef Firhat Bin Mohd Rodzi

**Platform:** Amazon S3 on LocalStack  
**Topics:** Bucket exposure, resource policies, SSE-KMS, versioning, lifecycle, retention, and provable deletion

## One-Time Environment Setup

The lab was configured to use a clean LocalStack instance with IAM enforcement enabled (`ENFORCE_IAM=1`) and the AWS CLI pointed to `http://localhost:4566`.

![One-time environment setup](<One-Time Environment Setup.png>)

## Task 1 - Classify the Data Before You Store It

The bucket contains three objects with different sensitivity levels. Object storage uses a flat namespace; for example, `confidential/record.txt` uses a key prefix and is not a physical folder.

| Classification | Who may read it | Impact if leaked | Control applied |
|---|---|---|---|
| Public | Anyone, because the content is intentionally public | Low impact; only general visiting information is exposed | Keep it non-sensitive, tag it `classification=public`, and do not place confidential data under the public prefix |
| Internal | Authenticated hospital staff and approved account principals | Operational information such as staff schedules may be exposed | Least-privilege bucket policy scoped to `internal/*`, plus Block Public Access |
| Confidential | Explicitly authorised clinical and security personnel only | Serious privacy, legal, and patient-safety impact | Block Public Access, explicit deny for unauthorised principals, SSE-KMS, versioning, lifecycle retention, and controlled deletion |

The classification tag on the confidential object is evidence that classification was applied before access decisions were made.

![Task 1 object listing](<Task 1  Classify the Data Before You Store It (1).png>)

![Task 1 classification evidence](<Task 1  Classify the Data Before You Store It (2).png>)

![Task 1 confidential object tag](<Task 1  Classify the Data Before You Store It (3).png>)

## Task 2 - Reproduce the Archetypal Breach

The deliberately unsafe bucket policy allowed `s3:GetObject` on every object to `Principal: "*"`. An unauthenticated HTTP request could therefore read `confidential/record.txt` and return HTTP 200.

The single policy element that caused the exposure was:

```json
"Principal": "*"
```

This means every principal, including anonymous callers, is covered by the allow statement. The combination of `s3:GetObject` and `arn:aws:s3:::BUCKET/*` then grants those callers read access to every object in the bucket.

![Task 2 anonymous read and leaked record](<Task 2 Reproduce the Archetypal Breach.png>)

## Task 3 - Remediate with Block Public Access

The public policy was removed and all four Block Public Access settings were enabled:

```text
BlockPublicAcls=true
IgnorePublicAcls=true
BlockPublicPolicy=true
RestrictPublicBuckets=true
```

On real Amazon S3, `BlockPublicPolicy=true` would reject the bucket policy that grants access to `Principal: "*"`. The other flags protect against public access through ACLs and restrict the effect of public policies. LocalStack may record the settings without enforcing every rejection, so the stored configuration and the anonymous-read retest are the appropriate evidence for this lab.

A preventative guardrail is stronger than a detective control because it blocks an unsafe change at the time it is attempted. A detective control only reports the exposure after it exists, leaving a window in which data can be accessed or copied.

The least-privilege policy should grant only the account root principal access to the internal prefix:

```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::BUCKET/internal/*"
}
```

![Task 3 public access block configuration](<Task 3 Remediate with Block Public Access (1).png>)

![Task 3 policy remediation](<Task 3 Remediate with Block Public Access (2).png>)

![Task 3 anonymous read retest](<Task 3 Remediate with Block Public Access (3).png>)

## Task 4 - Identity Policy vs Resource Policy

The analyst identity policy allows `s3:GetObject` and `s3:ListBucket` on `Resource: "*"`. The bucket resource policy permits the analyst to read `internal/*` but explicitly denies `s3:*` on `confidential/*`.

| Request | Evaluation | Result | Deciding statement |
|---|---|---|---|
| Read `internal/roster.txt` | No explicit deny applies and both policies allow the request | Allowed | `AllowAnalystInternal` in the bucket policy, together with the analyst identity allow |
| Read `confidential/record.txt` | The analyst identity allows it, but the bucket policy contains an explicit deny | Denied | `DenyAnalystConfidential`; an explicit deny overrides all allows |

The evaluation order is: default deny, then any explicit deny, then an applicable explicit allow. If LocalStack does not enforce IAM, the written policy documents and this evaluation logic are the evidence.

![Task 4 analyst policy](<Task 4 Identity Policy vs Resource Policy (1).png>)

![Task 4 internal access](<Task 4 Identity Policy vs Resource Policy (2).png>)

![Task 4 confidential access denied](<Task 4 Identity Policy vs Resource Policy (3).png>)

## Task 5 - Default Encryption at Rest (SSE-KMS)

The bucket was configured with a customer-managed KMS key and default server-side encryption:

```json
{
  "SSEAlgorithm": "aws:kms",
  "KMSMasterKeyID": "KEY_ID",
  "BucketKeyEnabled": true
}
```

The object was uploaded without encryption flags, but `head-object` reported `aws:kms`, the key ID, and bucket-key usage. This proves that encryption was enforced by the bucket rather than relying on each uploader to remember it.

![Task 5 KMS key and bucket encryption](<Task 5 Default Encryption at Rest (SSE-KMS) (1).png>)

![Task 5 encrypted object metadata](<Task 5 Default Encryption at Rest (SSE-KMS) (2).png>)

## Task 6 - Delegated Access and the Condition-Key Trap

A presigned URL grants a specific operation on a specific object for a limited period. The URL carries a signature and expiry information, so anyone who obtains it before expiry can use that URL without having an AWS identity. The URL must therefore be treated like a temporary bearer credential.

The important URL values are:

| Parameter | Meaning |
|---|---|
| `X-Amz-Expires` or `Expires` | The permitted lifetime of the signed request |
| `X-Amz-Signature` or `Signature` | Cryptographic proof that the signer authorised the exact request |
| Object path and signed query values | Bind the permission to the selected object and operation rather than to the whole bucket |

The `aws:SecureTransport` policy is correct for an HTTPS production endpoint, but it locks out this lab because LocalStack uses plain HTTP. Every request evaluates the condition as `false`, so the explicit deny matches all principals and all S3 actions. Conditions must be evaluated against the environment where the policy runs; a policy written for HTTPS cannot be tested as though the endpoint were HTTP.

![Task 6 presigned URL](<Task 6 Delegated Access and the Condition Key Trap (1).png>)

![Task 6 transport policy](<Task 6 Delegated Access and the Condition Key Trap (2).png>)

![Task 6 policy failure and recovery](<Task 6 Delegated Access and the Condition Key Trap (3).png>)

## Task 7 - Versioning, Delete Markers, and Data Remanence

After versioning was enabled, each upload created a version. Deleting the object created a delete marker and hid the current object from an ordinary read; it did not remove earlier versions. The original unredacted record could still be recovered with `--version-id null`.

Therefore, `delete-object` alone is not compliant with an erasure request. It changes the current view of the key but leaves historical versions available. A complete deletion must remove every version and every delete marker by ID.

Two mechanisms that make deletion more provable are:

1. Enumerate all versions and delete each version and delete marker, then retain the version listing and successful deletion output as audit evidence.
2. Use cryptographic erasure by disabling or destroying the customer-managed KMS key that protects the objects, and retain the KMS key-state evidence and failed decrypt as proof that the ciphertext is no longer recoverable.

![Task 7 version listing](<Task 7 — Versioning, Delete Markers & Data Remanence (1).png>)

![Task 7 delete marker](<Task 7 — Versioning, Delete Markers & Data Remanence (2).png>)

![Task 7 recovered original record](<Task 7 — Versioning, Delete Markers & Data Remanence (3).png>)

## Task 8 - Lifecycle, Retention, and Cryptographic Erasure

The lifecycle configuration expresses the retention policy:

| Rule | Scope | Action |
|---|---|---|
| `RetireConfidentialRecords` | `confidential/` | Expire current objects after 365 days and noncurrent versions after 30 days |
| `AbortIncompleteUploads` | Entire bucket | Abort incomplete multipart uploads after 7 days |

The KMS key was inspected, disabled, and scheduled for deletion with a seven-day pending window. Destroying the key makes objects encrypted under it unrecoverable even when copies, versions, or backups remain. This gives an auditor stronger assurance than overwriting because the cloud customer does not control every physical storage location or replica; without the decryption key, the retained ciphertext is unusable.

LocalStack may still return an object after key disablement because it may not re-check KMS key state during S3 reads. In that case, the KMS-layer `encrypt -> disable-key -> decrypt` test is the correct additional evidence.

![Task 8 lifecycle configuration](<Task 8  Lifecycle, Retention & Cryptographic Erasure (1).png>)

![Task 8 KMS key state and erasure](<Task 8  Lifecycle, Retention & Cryptographic Erasure (2).png>)

## Short-Answer Questions

### 1. Which policy element caused the Task 2 exposure?

`Principal: "*"` caused the exposure because it includes every principal, including anonymous callers. In a bucket policy, this can expose the resource to the entire internet. An over-broad identity policy attached to one user is still dangerous, but its direct scope is limited to that identity and any credentials or roles it can use; a public resource policy can be reached by anyone who can discover the object endpoint.

### 2. Identity-based policy versus resource-based policy

An identity-based policy is attached to a user, group, or role and describes what that identity may do. A resource-based policy is attached to the bucket and describes which principals may access that bucket and its objects. Both must be considered together. In Task 4, the internal request was decided by the analyst allow plus `AllowAnalystInternal`; the confidential request was decided by `DenyAnalystConfidential`, because an explicit deny overrides the identity-based allow.

### 3. Why is Block Public Access a guardrail?

A guardrail is a preventative boundary that stops an unsafe configuration from being applied or used. A normal control may grant or check access, while a detective control only finds a problem after it exists. Block Public Access matters in a large organisation because it provides a consistent account or bucket-level safety boundary even when many engineers create policies independently.

### 4. Does SSE-KMS protect the record from the analyst?

No. SSE-KMS protects the object while it is stored by encrypting its data and managing the encryption key. It does not replace authorisation and does not stop an authorised S3 read. If the analyst is allowed to call `GetObject`, S3 decrypts the object on behalf of that request and returns plaintext. The bucket policy deny in Task 4, not SSE-KMS, prevents the analyst from reading the confidential record.

### 5. Why is `delete-object` insufficient, and what proves deletion?

With versioning enabled, `delete-object` normally creates a delete marker. Older versions remain addressable and may contain the original diagnosis. Provable deletion can be achieved by enumerating and deleting every object version and delete marker, with the resulting empty version listing kept as evidence. A second mechanism is cryptographic erasure: disable or destroy the KMS key and retain the key-state and failed-decrypt evidence.

### 6. Three commands an auditor should collect

| Command | Control evidenced |
|---|---|
| `aws $EP s3api get-public-access-block --bucket $BUCKET` | All four public-access guardrails are enabled |
| `aws $EP s3api get-bucket-encryption --bucket $BUCKET` | Default SSE-KMS encryption is configured |
| `aws $EP s3api list-object-versions --bucket $BUCKET` | Versioning state, delete markers, retained versions, and deletion evidence |

Other useful evidence includes `head-object` for the actual encryption metadata, `get-bucket-lifecycle-configuration` for retention, and `kms describe-key` for the KMS key state.

## Verification Command

The final verification should show Block Public Access, versioning, SSE-KMS, lifecycle rules, and the final KMS key state for the actual bucket and key created during the lab.

![Final verification command](<Verification Command.png>)

```text
=== IKB42603 Lab 6 verification: BUCKET ===
BlockPublicAcls       TRUE
IgnorePublicAcls      TRUE
BlockPublicPolicy     TRUE
RestrictPublicBuckets TRUE
Enabled
aws:kms KEY_ID
RetireConfidentialRecords Enabled
AbortIncompleteUploads Enabled
PendingDeletion
```

The bucket name and KMS key ID are environment-specific values and should be retained from the actual LocalStack command output rather than replaced with the literal placeholders above.

## Security Checklist

- [x] Every object has a classification tag.
- [x] The public policy was identified and removed.
- [x] Block Public Access is enabled on all four flags.
- [x] Access is scoped to the required key prefix.
- [x] Default encryption uses `aws:kms` with a customer-managed key.
- [x] Sharing uses a time-bounded presigned URL.
- [x] Versioning and delete-marker behaviour were demonstrated.
- [x] Lifecycle retention and cryptographic erasure were documented.
