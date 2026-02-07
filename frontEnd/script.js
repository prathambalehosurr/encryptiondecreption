document.addEventListener("DOMContentLoaded", function () {

    const fileInput = document.getElementById("fileInput");
    const inputTextarea = document.getElementById("ip");

    fileInput.addEventListener("change", function () {
        const file = this.files[0];
        if (!file) {
            alert("No file selected");
            return;
        }

        const reader = new FileReader();

        reader.onload = function () {
            inputTextarea.value = reader.result;
        };

        reader.onerror = function () {
            alert("Error reading file");
        };

        reader.readAsText(file);
    });

});