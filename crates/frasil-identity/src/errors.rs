//! The error classes identity.md defines (identity.md, "Error classes").
//!
//! `Full` is overview.md's shared class, which identity.md's table repeats
//! for list events; it is [`ErrorClass::Full`](frasil_base::ErrorClass::Full).

frasil_base::error_classes! {
    /// The classes identity.md defines, and every shared class.
    pub enum IdentityClass {
        /// A first list event that is not a device adding itself.
        BadGenesis = "bad_genesis", Final;
        /// The author is not an active list member, or may not sign this.
        UntrustedSigner = "untrusted_signer", Final;
        /// An agent, or a list member rooted in one, beyond what it may do.
        AgentLimited = "agent_limited", Final;
        /// An `add` naming a key already on the list, or a concurrent `add`
        /// that comes first.
        AlreadyListed = "already_listed", Final;
        /// A `revoke` or `confirm` naming no active list member of that kind.
        NotListed = "not_listed", Final;
        /// A rooted author revoking a recovery key other than itself.
        RecoveryKeyProtected = "recovery_key_protected", Final;
        /// A `confirm` of a list member that is not a rooted device or
        /// recovery key.
        NotPending = "not_pending", Final;
        /// A revocation that leaves no active list member but agents.
        LastMember = "last_member", Final;
        /// A list event neither in the past of the list checkpoint in
        /// effect nor after it (identity.md, "List checkpoints").
        Late = "late", Final;
        /// A list event after a list checkpoint with a parent, other than
        /// its `prev`, that is neither the checkpoint nor after it.
        MixedCut = "mixed_cut", Final;
        /// A list event whose `follows` are not those its parents give.
        BadCuts = "bad_cuts", Final;
        /// A list checkpoint whose predecessor or record is not that of its
        /// past.
        BadCheckpoint = "bad_checkpoint", Final;
        /// A list checkpoint whose past holds another valid checkpoint, or
        /// whose predecessor is not in effect there.
        CheckpointPending = "checkpoint_pending", Final;
        /// An event of a list member that a concurrent valid revocation
        /// names.
        RevokedConcurrently = "revoked_concurrently", Final;
        /// A `confirm` of a list member that a concurrent valid revocation
        /// names.
        TargetRevokedConcurrently = "target_revoked_concurrently", Final;
        /// A link, list or handle for another person.
        WrongPerson = "wrong_person", Final;
        /// A link that a valid unlink names.
        Unlinked = "unlinked", Final;
        /// A person ID of the wrong length.
        InvalidPersonId = "invalid_person_id", Decision;
        /// A PRF output of the wrong length.
        InvalidPrfOutput = "invalid_prf_output", Decision;
        /// Printed text that is not a recovery secret.
        InvalidSheet = "invalid_sheet", Decision;
        /// Two PRF evaluations derived different keys.
        UnstablePrf = "unstable_prf", Decision;
        /// A derived list member that is not an active list member of the
        /// merged list.
        NotOnList = "not_on_list", Decision;
        /// Text that is not a fingerprint.
        InvalidFingerprint = "invalid_fingerprint", Decision;
        /// A fingerprint whose check character fails: a typing error.
        FingerprintMistyped = "fingerprint_mistyped", Decision;
        /// Keys whose fingerprint is not the one confirmed.
        FingerprintMismatch = "fingerprint_mismatch", Decision;
        /// An offered list lacks an event the client pinned.
        RolledBack = "rolled_back", Report;
        /// An offered list holds new evidence that a list member forked.
        ForkDetected = "fork_detected", Report;
    }
}

#[cfg(test)]
mod tests {
    use super::IdentityClass;
    use frasil_base::errors::{Class, ErrorClass, Sort, snake_case};

    #[test]
    fn wire_names_are_snake_case() {
        for class in IdentityClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
            assert_eq!(IdentityClass::from_name(class.name()), Some(*class));
        }
    }

    #[test]
    fn shared_classes_lift() {
        assert_eq!(
            IdentityClass::from_name("Full"),
            Some(IdentityClass::Shared(ErrorClass::Full))
        );
        assert_eq!(IdentityClass::RolledBack.sort(), Sort::Report);
        assert_eq!(IdentityClass::BadGenesis.sort(), Sort::Final);
        assert_eq!(IdentityClass::InvalidSheet.sort(), Sort::Decision);
    }
}
