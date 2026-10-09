(() => {
    const drawer = document.getElementById("intelDrawer");
    const closeBtn = document.getElementById("closeDrawer");
    const openButtons = document.querySelectorAll("[data-open-drawer]");
    const search = document.querySelector(".global-search input");

    function openDrawer() {
        if (!drawer) return;

        drawer.classList.add("open");
        drawer.setAttribute("aria-hidden", "false");
    }

    function closeDrawer() {
        if (!drawer) return;

        drawer.classList.remove("open");
        drawer.setAttribute("aria-hidden", "true");
    }

    openButtons.forEach((button) => {
        button.addEventListener("click", openDrawer);
    });

    if (closeBtn) {
        closeBtn.addEventListener("click", closeDrawer);
    }

    document.addEventListener("keydown", (event) => {
        const active = document.activeElement;

        const editable = active && (
            active.tagName === "INPUT"
            || active.tagName === "TEXTAREA"
            || active.isContentEditable
        );

        if (
            event.key === "/"
            && !editable
            && search
        ) {
            event.preventDefault();
            search.focus();
        }

        if (event.key === "Escape") {
            closeDrawer();
        }
    });
})();
