package dissect

import "fmt"

// CraftVersionNegotiation builds a VN packet advertising QUICv1 + GREASE versions.
// dcid/scid are echoed from the client's Initial (server mirrors them).
func CraftVersionNegotiation(dcid, scid []byte, versions []uint32) []byte {
	if versions == nil {
		versions = []uint32{
			0x1a2a3a4a, // GREASE
			QUICVersion1,
			0x5a6a7a8a, // GREASE
		}
	}
	b := []byte{0x80 | 0x7f} // long header, unused bits arbitrary
	b = append(b, 0, 0, 0, 0) // version = 0
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	for _, v := range versions {
		b = append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return b
}

// CraftRetry builds a QUICv1 Retry with a valid integrity tag.
// odcid = client's first Initial DCID; retryDCID = client's SCID (echoed);
// scid = server-chosen CID; token = opaque.
func CraftRetry(odcid, retryDCID, scid, token []byte) ([]byte, error) {
	first := byte(0xc0 | (QUICLongRetry << 4)) // form+fixed+Retry
	body := []byte{first}
	body = append(body, byte(QUICVersion1>>24), byte(QUICVersion1>>16), byte(QUICVersion1>>8), byte(QUICVersion1))
	body = append(body, byte(len(retryDCID)))
	body = append(body, retryDCID...)
	body = append(body, byte(len(scid)))
	body = append(body, scid...)
	body = append(body, token...)
	tag, err := ComputeRetryIntegrityTag(body, odcid)
	if err != nil {
		return nil, err
	}
	return append(body, tag...), nil
}

// CraftRetryChromeLike returns a Retry matching CraftChromeLikeInitial CIDs.
func CraftRetryChromeLike() ([]byte, error) {
	odcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	clientSCID := []byte{0x11}
	serverSCID := []byte{0xf0, 0x67, 0xa5, 0x50, 0x2b}
	token := []byte("coherencelab-retry-token")
	return CraftRetry(odcid, clientSCID, serverSCID, token)
}

// CraftVNChromeLike mirrors a client Initial's CIDs into a greased VN.
func CraftVNChromeLike() []byte {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x11}
	return CraftVersionNegotiation(dcid, scid, nil)
}

// ODCIDFromChromeLikeInitial is the DCID used by CraftChromeLikeInitial / CraftRetryChromeLike.
func ODCIDFromChromeLikeInitial() []byte {
	return []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
}

// Ensure Format helpers can name grease versions.
func formatVersion(v uint32) string {
	if IsQUICVersionGREASE(v) {
		return fmt.Sprintf("0x%08x (GREASE)", v)
	}
	if v == QUICVersion1 {
		return "0x00000001 (QUICv1)"
	}
	if v == 0 {
		return "0x00000000 (VN)"
	}
	return fmt.Sprintf("0x%08x", v)
}
