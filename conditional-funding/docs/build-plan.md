# conditional-funding — План сборки

Первый не-`DONE` этап — текущий. DoD/тесты — `docs/spec.md` + `crown-spec/docs/01-standards.md`.
Контракт игр — `games-harness.md`. Не заморожена.

| Этап | Что | Статус |
|---|---|---|
| F0 | Скелет: `logic/`+`canister/`, CI, границы | DONE |
| F1 | `logic/` — машина сбора + вердикт с кворумом (`quorum_weight`, `approval_threshold`) + тесты | DONE¹ |
| F2 | Канистра: `create_collection` (ленивая деривация, снимок профиля в прообразе), материализация на первом вкладе, `ready`/`recipient_cancel`, дериватный резолвер per-collection | DONE² |
| F3 | Голосование весом книги: пруф локально, валидность в `inspect_message`, дедуп, `V_MAX` | DONE³ |
| F4 | Подпись по требованию (оплаченный pull), атомарный вердикт на N эскроу, правило подписи | DONE⁴ |
| F5 | E2e через реальную сеть: сбор → вклады → голос → всем расчёт/возврат | TODO |
| F6 | Прод-деплой | TODO |

DoD не-отрицательности (`cost.md §6`): F2 — `create_collection`/`ready`/`cancel` без пруфа рождения не
растят память; F3 — нулевой голос не доходит до `update`; F4 — правило подписи на каждую подпись, атомарно.

² F2: `create_collection` (получатель-подписант) пересчитывает `collection_id` из предъявленных полей + снимка конфига (`voting_period`/`approval_threshold`/`quorum_weight`) и сверяет с подписанным `collection`; деривует резолвер `key([collection_id])`. **С пруфом рождения** первого вклада — верифицирует его на деривуемом адресе эскроу (BLS-сертификат индекса → корень → свидетель → рождение; крипта общая — `crown-games-common`) и материализует `Funding`, фиксируя `created_at`. **Без пруфа** — эхо деривации, ноль записи (DoD не-негативности). `ready`/`recipient_cancel` — самоподписаны, не материализуют (`NotFound` на неоматериализованном). Слот→время: линейный якорь (`slot_ms`/`genesis_slot`/`genesis_unix` в `config/`, изолирован в `config::slot_to_created_at`; плейсхолдеры до F5(devnet)/P8(mainnet), фриз-гейт `genesis_unix≠0` на mainnet). Общая крипта вынесена в `crown-games-common` (единый источник BLS/threshold-деривации; `conditional-tasks` репойнтнут, тесты держат). `vote`/`request_signature` — типизированные заглушки до F3/F4. 50 тестов (logic 14 + канистра 17 + common 19), clippy strict/fmt/wasm/.did чисто.

³ F3: `vote` — вес = репутация голосующего к получателю сбора, доказывается свидетелем книги против сертифицированного корня индекса (`birth::reputation_from_witness`, крипта общая); `choice ∈ {done,not_done}`; запись через `step` (только в `Voting`, порог `MIN_VOTE_WEIGHT`, дедуп `(collection_id, voter)`), кэп `V_MAX=500`. Валидность (подпись+таргет+вес ≥ порога) отбивается бесплатно в `inspect_message` до исполнения (нулевой/невалидный не доходит до `update`). Дедуп/порог/кэп покрыты тестами `state.rs`; рантайм-гейт `inspect_message` — на F5.

⁴ F4: `request_signature(chain, collection)` — оплаченный pull (фронтит релеер за `SIGN_PRICE`): проверка оплаты (`msg_cycles_available ≥ SIGN_PRICE` → иначе `Underpaid`) и таргета до `sign_with_schnorr`; неготовый вердикт → `NotDecided` **без списания**. `verdict(collection_id)` → `outcome` (settle=0/refund=1); списание принимается **только** перед подписью. **Одна** подпись `key([collection_id])` над `verdict_message(DOMAIN, program_id, outcome)` переиспользуется всеми N эскроу (все деривуют этот резолвер) — это и есть атомарность: один исход на весь сбор, без Merkle-корня/пути. `verdict_message` общий (форма two-outcome). Реальная threshold-подпись + сеть — на F5.

¹ F1: `logic/` zero-dep — машина `Funding→Voting{started_at}→Decided` (окна: `[created_at, created_at+duration]` от slot→время рождения; `[started_at, started_at+voting_period]`; границы строго `>=`; время до действия; overflow не двигает состояние). Вердикт **с кворумом**: `turnout=yes+no ≥ quorum_weight` **и** `yes·10000 > approval_threshold·turnout` (строго) → settle; ничья/недобор/пусто/overflow → refund. 14 тестов (property: settle-iff-rule; unit: границы окон, silence→refund, дедуп/порог, decided-absorbing, overflow). clippy strict/fmt чисто.
