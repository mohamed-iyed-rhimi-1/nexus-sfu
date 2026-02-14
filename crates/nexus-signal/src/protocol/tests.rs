use super::*;

#[cfg(test)]
mod roundtrip_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_signal_message_roundtrip(
            room_id in "[a-z0-9-]{1,50}",
            participant_name in "[a-z0-9-]{1,50}",
        ) {
            let builder = MessageBuilder::new(4096);

            // Serialize
            let bytes = builder.build_signal_message(|msg| {
                let mut join = msg.init_join();
                join.set_room_id(&room_id);
                join.set_participant_name(&participant_name);
                join.set_schema_version(1);
            });

            // Deserialize
            let reader = MessageReader::new();
            let msg_reader = reader.read_signal_message(&bytes).unwrap();
            let msg = msg_reader.get_root::<signaling_capnp::signal_message::Reader>().unwrap();

            // Assert round-trip property using which()
            assert!(msg.has_join());
            match msg.which().unwrap() {
                signaling_capnp::signal_message::Which::Join(join_result) => {
                    let join = join_result.unwrap();
                    assert_eq!(join.get_room_id().unwrap(), room_id);
                    assert_eq!(join.get_participant_name().unwrap(), participant_name);
                    assert_eq!(join.get_schema_version(), 1);
                }
                _ => panic!("Expected Join variant"),
            }
        }

        #[test]
        fn test_ice_candidate_roundtrip(
            candidate in "[a-zA-Z0-9:. ]{1,200}",
            sdp_mid in "[a-z0-9]{1,20}",
            sdp_mline_index in 0u32..10,
        ) {
            let builder = MessageBuilder::new(4096);

            let bytes = builder.build_signal_message(|msg| {
                let mut ice = msg.init_ice_candidate();
                ice.set_candidate(&candidate);
                ice.set_sdp_mid(&sdp_mid);
                ice.set_sdp_mline_index(sdp_mline_index);
                ice.set_schema_version(1);
            });

            let reader = MessageReader::new();
            let msg_reader = reader.read_signal_message(&bytes).unwrap();
            let msg = msg_reader.get_root::<signaling_capnp::signal_message::Reader>().unwrap();

            assert!(msg.has_ice_candidate());
            match msg.which().unwrap() {
                signaling_capnp::signal_message::Which::IceCandidate(ice_result) => {
                    let ice = ice_result.unwrap();
                    assert_eq!(ice.get_candidate().unwrap(), candidate);
                    assert_eq!(ice.get_sdp_mid().unwrap(), sdp_mid);
                    assert_eq!(ice.get_sdp_mline_index(), sdp_mline_index);
                }
                _ => panic!("Expected IceCandidate variant"),
            }
        }
    }

    #[test]
    fn test_all_signal_message_variants() {
        let builder = MessageBuilder::new(4096);
        let reader = MessageReader::new();

        // Test Join
        let bytes = builder.build_signal_message(|msg| {
            let mut join = msg.init_join();
            join.set_room_id("test");
            join.set_participant_name("alice");
        });
        let msg_reader = reader.read_signal_message(&bytes).unwrap();
        let msg = msg_reader.get_root::<signaling_capnp::signal_message::Reader>().unwrap();
        assert!(msg.has_join());

        // Test Offer
        let bytes = builder.build_signal_message(|msg| {
            let mut offer = msg.init_offer();
            offer.set_sdp("v=0...");
        });
        let msg_reader = reader.read_signal_message(&bytes).unwrap();
        let msg = msg_reader.get_root::<signaling_capnp::signal_message::Reader>().unwrap();
        assert!(msg.has_offer());

        // Test Answer
        let bytes = builder.build_signal_message(|msg| {
            let mut answer = msg.init_answer();
            answer.set_sdp("v=0...");
        });
        let msg_reader = reader.read_signal_message(&bytes).unwrap();
        let msg = msg_reader.get_root::<signaling_capnp::signal_message::Reader>().unwrap();
        assert!(msg.has_answer());

        // Test IceCandidate
        let bytes = builder.build_signal_message(|msg| {
            let mut ice = msg.init_ice_candidate();
            ice.set_candidate("candidate:...");
            ice.set_sdp_mid("0");
            ice.set_sdp_mline_index(0);
        });
        let msg_reader = reader.read_signal_message(&bytes).unwrap();
        let msg = msg_reader.get_root::<signaling_capnp::signal_message::Reader>().unwrap();
        assert!(msg.has_ice_candidate());

        // Test Leave - use which() to check for Leave variant
        let bytes = builder.build_signal_message(|mut msg| {
            msg.set_leave(());
        });
        let msg_reader = reader.read_signal_message(&bytes).unwrap();
        let msg = msg_reader.get_root::<signaling_capnp::signal_message::Reader>().unwrap();
        match msg.which().unwrap() {
            signaling_capnp::signal_message::Which::Leave(()) => {}
            _ => panic!("Expected Leave variant"),
        }
    }
}
