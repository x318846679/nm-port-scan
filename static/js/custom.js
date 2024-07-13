document.addEventListener('DOMContentLoaded', function () {
    // 处理编辑按钮点击事件
    document.querySelectorAll('.btn-warning').forEach(function (button) {
        button.addEventListener('click', function (event) {
            var userId = this.dataset.userId;
            fetch('/get_user/' + userId)
                .then(response => response.json())
                .then(data => {
                    document.querySelector('#editUserForm [name="username"]').value = data.username;
                    document.querySelector('#editUserForm [name="role"]').value = data.role;
                    document.querySelector('#editUserForm').action = '/edit-user/' + userId;

                    var modal = new bootstrap.Modal(document.getElementById('editUserModal'));
                    modal.show();
                })
                .catch(err => console.error(err));
        });
    });

    // 处理编辑用户表单提交
    document.querySelector('#editUserForm').addEventListener('submit', function (e) {
        e.preventDefault();
        var form = this;
        var actionUrl = form.action;
        var formData = new FormData(form);

        fetch(actionUrl, {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                console.log(data.success)
                if (data.success) {
                    // 隐藏模态框
                    var modal = bootstrap.Modal.getInstance(document.getElementById('editUserModal'));
                    modal.hide(); // 隐藏模态框
                    location.reload(); // 刷新页面以查看更改
                } else {
                    alert('更新失败');
                }
            })
            .catch(err => console.error(err));
    });
});
