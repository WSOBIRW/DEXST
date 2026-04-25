pub fn t(key: &'static str) -> &'static str {
    match key {
        // Главное меню
        "menu.file" => "Файл",
        "menu.edit" => "Правка",
        "menu.view" => "Вид",
        "menu.help" => "Помощь",
        "menu.workspace" => "Рабочее пространство",
        "menu.project" => "Проект",
        "menu.terminal" => "Терминал",

        // Панели
        "panel.project" => "Проект",
        "panel.outline" => "Структура",
        "panel.terminal" => "Терминал",
        "panel.debugger" => "Отладчик",
        "panel.ai" => "AI-наблюдатель",
        "panel.git" => "Git",
        "panel.collab" => "Совместная работа",

        "menu.selection" => "Выделение",
        "menu.go" => "Переход",
        "menu.run" => "Запуск",
        "menu.window" => "Окно",
        _ => key,
    }
}
