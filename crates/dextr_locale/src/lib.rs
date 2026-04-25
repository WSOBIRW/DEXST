/// Система локализации DEXTR STUDIO.
/// Возвращает перевод для ключа, либо сам ключ, если перевод отсутствует.
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

        // Действия
        "action.open_workspace" => "Открыть рабочее пространство",
        "action.close_workspace" => "Закрыть рабочее пространство",
        "action.search" => "Поиск",
        "action.go_to_definition" => "Перейти к определению",

        // Все остальные ключи остаются как есть (английские)
        _ => key,
    }
}
