# conditional-tasks — План сборки

Первый не-`DONE` этап — текущий. DoD и тесты — `docs/spec.md` + `crown-spec/docs/01-standards.md`.
Контракт игр — `games-harness.md`. Игра не заморожена (заменяется новой канистрой, старая доживает).

| Этап | Что | Статус |
|---|---|---|
| T0 | Скелет: `logic/` + `canister/`, CI, границы (zero-dep logic, нет сетей, нет таймеров) | DONE |
| T1 | `logic/` — машина `Created→Accepted/Declined→Ready→Voting→Decided` + правило вердикта + тесты | DONE¹ |
| T2 | Канистра: `register_task` (ленивая деривация), материализация на пруфе рождения, `accept`/`decline`/`ready`, текст-хеш, профиль | DONE² |
| T3 | Голосование весом книги: пруф веса локально, валидность в `inspect_message`, дедуп, `V_MAX` | DONE³ |
| T4 | Вердикт: per-task резолвер, root-verdict, оплаченный pull `request_signature`, правило подписи | DONE⁴ |
| T5 | E2e через реальную сеть (devnet): донат → задание → голос → расчёт/возврат | TODO |
| T6 | Прод-деплой (devnet свободен; передеплой свободен) | TODO |

Ключевые DoD не-отрицательности (`cost.md §6`, тест на каждый): T3 — голос нулевого кошелька не доходит
до `update`; T4 — правило подписи `f·Σgross ≥ scope_cost(V_MAX)·(1+MARGIN)` на каждую подпись; T2 —
`register_task` без пруфа рождения не растит стабильную память.

¹ T1: `logic/` zero-dep — машина `step = advance(время) → действие` (провал действия ≡ Tick, advance персистится; overflow времени → состояние не тронуто), исчерпывающий `match` без `_`; окна из `deadline` (`cutoff = deadline − voting_period − MARGIN`, `voting_end = deadline − MARGIN`); вердикт `settle ⇔ Σdone строго > Σnot_done`, иначе Cancel (ничья/пусто/overflow весов). 18 тестов (property: settle-iff-strictly-greater; unit: границы cutoff/voting_end точны, failed-action-is-tick, decided-absorbing, дедуп/порог, overflow не двигает состояние). `clippy` strict (checked-арифметика, без unwrap/panic/indexing) чист.

² T2: канистра собрана из проверенных модулей — `protocol` (task_id+сообщения+Ed25519), `validate` (порядок отказов регистрации), `address` (PDA эскроу), `birth` (BLS-сертификат индекса против NNS root key — провалидировано PocketIC-тестом против **реального** сертификата — + свидетель рождения + пруф репутации), `resolver` (threshold-Ed25519 деривация крейтом-референсом IC; public==private тест), `request` (wire-формат+подпись), `state` (in-memory оркестрация: материализация идемпотентна, авторизация signer==recipient, ленивый tick, счётчик профиля), `config` (бейк). Эндпоинты (`init` с mainnet-trap, `bootstrap` мастер-ключа, `register_task`, `accept`/`decline`/`ready`, `set_profile`, queries; `vote`/`request_signature` — T3/T4) panic-free (let-else), собраны в wasm, `.did` сгенерирован. **56 тестов** (18 logic + 35 unit + 3 PocketIC birth-e2e), clippy/fmt/wasm чисто. Полный флоу register→голос→расчёт — на реальном devnet (T5).

³ T3: голос. `inspect_message` — **бесплатный гейт валидности** (метод==vote → подпись + target + пруф веса `reputation_from_witness(voter,recipient) ≥ MIN_VOTE_WEIGHT`; невалидный не доходит до исполнения — инв. #2). `vote` endpoint: пруф веса → `state::add_vote` (дедуп `(task_id,voter)` + порог + `Voting`-state через `step`, кэп `V_MAX=500` — инв. #7). Вес = репутация голосующего к получателю задания (пруф книги против сертифицированного корня индекса). `state::add_vote` host-тестирован (запись/дедуп/порог/V_MAX/не-Voting). **58 тестов**, clippy/fmt/wasm/.did чисто. Полный флоу голосования — на реальном devnet (T5).

⁴ T4: вердикт. `protocol::verdict_message(domain ‖ program_id(32) ‖ u8(outcome))` — байт-точно с ончейн-проверкой формы two-outcome (settle=0/cancel=1), пиннут тестом. `request_signature(chain,task)` — **оплаченный pull**: `msg_cycles_available ≥ SIGN_PRICE` → валидация → вердикт из `state::verdict` (не-`Decided` → отказ **без списания**) → `msg_cycles_accept(SIGN_PRICE)` **до** `sign_with_schnorr` → подпись резолвером `sign_with_schnorr(path=[task_id], Ed25519, verdict_message)` → `Signed{outcome,sig}`. Одна подпись области, переиспользуемая эскроу (`claim(outcome,sig)`). `sign_price` вбит в конфиг (≤ релейного). **59 тестов**, clippy/fmt/wasm/.did чисто. Живой threshold-подпись — на devnet (T5).
