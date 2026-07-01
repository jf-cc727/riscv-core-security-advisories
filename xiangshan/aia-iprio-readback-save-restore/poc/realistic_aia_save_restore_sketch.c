/*
 *
 * Unique role of this file:
 *   show a realistic monitor / firmware lifecycle where trusted code saves and
 *   restores host-owned AIA priority state around an ordinary privilege
 *   boundary, and where a false-zero readback becomes persistent corruption of
 *   that host policy state after restore.
 */
#include <stdint.h>

#define MIE_SSIE               0x2u
#define IPRIO0_PRIOSSI_MASK    0x000000000000ff00ull
#define EXPECTED_PRIO_SSI      0x0000000000000100ull
#define PRIORITY_INTEGRITY_OK  0x5052494fu
#define PRIORITY_INTEGRITY_BAD 0x42414421u

struct aia_context_image {
    uint64_t saved_mie;
    uint64_t saved_iprio0;
};

struct host_irq_policy {
    uint64_t expected_iprio0;
    uint64_t restored_iprio0;
    uint64_t integrity_cookie;
    uint64_t degraded_restore_count;
    uint64_t boundary_count;
};

struct privilege_boundary {
    uint64_t requester_id;
    uint64_t reason;
};

struct aia_hw_view {
    uint64_t mie;
    uint64_t selected_iprio0;
};

static uint64_t read_selected_iprio0(const struct aia_hw_view *hw) {
    return hw->selected_iprio0;
}

static void write_selected_iprio0(struct aia_hw_view *hw, uint64_t value) {
    hw->selected_iprio0 = value;
}

static void save_host_aia_context(struct aia_hw_view *hw,
                                  struct aia_context_image *img) {
    /*
     * Trusted code masks delivery before the boundary, but expects the already
     * configured priority storage to remain architecturally visible.
     */
    hw->mie &= ~MIE_SSIE;
    img->saved_mie = hw->mie;
    img->saved_iprio0 = read_selected_iprio0(hw);
}

static void restore_host_aia_context(struct aia_hw_view *hw,
                                     const struct aia_context_image *img) {
    write_selected_iprio0(hw, img->saved_iprio0);
    hw->mie = img->saved_mie | MIE_SSIE;
}

static int verify_host_priority_integrity(const struct aia_hw_view *hw,
                                          struct host_irq_policy *policy) {
    policy->restored_iprio0 = read_selected_iprio0(hw) & IPRIO0_PRIOSSI_MASK;
    if (policy->restored_iprio0 == policy->expected_iprio0) {
        policy->integrity_cookie = PRIORITY_INTEGRITY_OK;
        return 0;
    }

    policy->integrity_cookie = PRIORITY_INTEGRITY_BAD;
    policy->degraded_restore_count++;
    return -1;
}

int monitor_round_trip_boundary(struct privilege_boundary *boundary,
                                struct aia_hw_view *hw,
                                struct aia_context_image *img,
                                struct host_irq_policy *policy) {
    (void)boundary;

    /*
     * The lower-privileged side only needs to trigger this ordinary boundary.
     * It does not directly access AIA CSRs; the corruption happens entirely in
     * the trusted save/restore path if readback is wrongly masked by mie.SSIE.
     */
    policy->boundary_count++;
    save_host_aia_context(hw, img);
    restore_host_aia_context(hw, img);
    return verify_host_priority_integrity(hw, policy);
}

void example_host_policy_init(struct host_irq_policy *policy,
                              struct aia_hw_view *hw) {
    policy->expected_iprio0 = EXPECTED_PRIO_SSI;
    policy->restored_iprio0 = EXPECTED_PRIO_SSI;
    policy->integrity_cookie = PRIORITY_INTEGRITY_OK;
    hw->mie = MIE_SSIE;
    hw->selected_iprio0 = EXPECTED_PRIO_SSI;
}

/*
 * On correct hardware:
 *   save sees iprio0.PrioSSI = 0x01 even while mie.SSIE is temporarily clear
 *   -> restore writes back 0x01
 *   -> host policy integrity remains OK
 *
 * On the vulnerable DUT:
 *   save sees false zero while mie.SSIE is clear
 *   -> restore writes back 0x00
 *   -> host-owned interrupt-priority policy remains silently degraded
 */
