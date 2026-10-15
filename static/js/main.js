/* =========================================================
   SECURE FILE GATEWAY
   Main Dashboard JavaScript
========================================================= */

"use strict";


/* =========================================================
   SHARE MODAL
========================================================= */

let currentShareFileId = null;


/**
 * Open the secure share modal.
 *
 * @param {number} fileId
 * @param {string} fileName
 */
function openShareModal(fileId, fileName) {

    const modalBackdrop = document.getElementById(
        "shareModalBackdrop"
    );

    const modalFileName = document.getElementById(
        "shareModalFileName"
    );

    const shareForm = document.getElementById(
        "shareForm"
    );

    const maxDownloads = document.getElementById(
        "shareMaxDownloads"
    );

    const expiresIn = document.getElementById(
        "shareExpiresIn"
    );


    if (!modalBackdrop || !modalFileName || !shareForm) {
        console.error(
            "Share modal elements were not found."
        );

        return;
    }


    /*
     * Store the selected file ID.
     */
    currentShareFileId = fileId;


    /*
     * Display selected file name.
     *
     * textContent is intentionally used instead of
     * innerHTML to prevent HTML injection.
     */
    modalFileName.textContent = fileName;


    /*
     * Configure the Flask POST endpoint.
     *
     * Example:
     * /share/15
     */
    shareForm.action = `/share/${encodeURIComponent(fileId)}`;


    /*
     * Reset form values every time the modal opens.
     */
    if (expiresIn) {
        expiresIn.value = "24";
    }


    if (maxDownloads) {
        maxDownloads.value = "";
    }


    /*
     * Reset submit button state.
     */
    resetShareSubmitButton();


    /*
     * Show modal.
     */
    modalBackdrop.classList.add("is-visible");

    modalBackdrop.setAttribute(
        "aria-hidden",
        "false"
    );


    /*
     * Prevent background scrolling.
     */
    document.body.classList.add("modal-open");


    /*
     * Move keyboard focus into the modal.
     */
    window.setTimeout(() => {

        if (expiresIn) {
            expiresIn.focus();
        }

    }, 100);
}


/**
 * Close the secure share modal.
 */
function closeShareModal() {

    const modalBackdrop = document.getElementById(
        "shareModalBackdrop"
    );


    if (!modalBackdrop) {
        return;
    }


    modalBackdrop.classList.remove("is-visible");

    modalBackdrop.setAttribute(
        "aria-hidden",
        "true"
    );


    /*
     * Restore page scrolling.
     */
    document.body.classList.remove("modal-open");


    /*
     * Clear selected file.
     */
    currentShareFileId = null;


    /*
     * Reset form state.
     */
    resetShareSubmitButton();
}


/**
 * Reset share submit button.
 */
function resetShareSubmitButton() {

    const submitButton = document.getElementById(
        "shareSubmitButton"
    );


    if (!submitButton) {
        return;
    }


    submitButton.disabled = false;

    submitButton.classList.remove(
        "is-loading"
    );

    submitButton.setAttribute(
        "aria-busy",
        "false"
    );
}


/**
 * Put share button into loading state.
 */
function setShareSubmitLoading() {

    const submitButton = document.getElementById(
        "shareSubmitButton"
    );


    if (!submitButton) {
        return;
    }


    submitButton.disabled = true;

    submitButton.classList.add(
        "is-loading"
    );

    submitButton.setAttribute(
        "aria-busy",
        "true"
    );
}


/* =========================================================
   SHARE FORM SUBMISSION
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        const shareForm = document.getElementById(
            "shareForm"
        );


        if (!shareForm) {
            return;
        }


        shareForm.addEventListener(
            "submit",
            (event) => {

                /*
                 * Let the browser perform normal
                 * POST navigation to Flask.
                 *
                 * We only change the UI to loading.
                 */
                setShareSubmitLoading();

            }
        );

    }
);


/* =========================================================
   MODAL BACKDROP CLICK
========================================================= */

document.addEventListener(
    "click",
    (event) => {

        const modalBackdrop = document.getElementById(
            "shareModalBackdrop"
        );


        if (!modalBackdrop) {
            return;
        }


        /*
         * Only close when the actual backdrop is clicked.
         *
         * Clicking inside the modal must NOT close it.
         */
        if (
            event.target === modalBackdrop &&
            modalBackdrop.classList.contains("is-visible")
        ) {

            closeShareModal();

        }

    }
);


/* =========================================================
   ESCAPE KEY
========================================================= */

document.addEventListener(
    "keydown",
    (event) => {

        if (event.key !== "Escape") {
            return;
        }


        const modalBackdrop = document.getElementById(
            "shareModalBackdrop"
        );


        if (
            modalBackdrop &&
            modalBackdrop.classList.contains("is-visible")
        ) {

            closeShareModal();

        }

    }
);


/* =========================================================
   DELETE CONFIRMATION
========================================================= */

function confirmDelete(fileName) {

    return window.confirm(
        `Are you sure you want to permanently delete "${fileName}"?`
    );
}