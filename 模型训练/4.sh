lr=2e-6
lora_rank=64
lora_alpha=128
lora_trainable="q_proj,v_proj,k_proj,o_proj,gate_proj,down_proj,up_proj"
modules_to_save="embed_tokens,lm_head"
lora_dropout=0.1

pretrained_model=/media/hnu/hnu2023/huangzhan/LLaMa-Model/chinese-alpaca-2-13b-for-exercise/complete-model
chinese_tokenizer_path=/media/hnu/hnu2023/huangzhan/Chinese-LLaMA-Alpaca-2-main/Chinese-LLaMA-Alpaca-2-main/scripts/tokenizer
dataset_dir=/media/hnu/hnu2023/huangzhan/training/alpaca/6/data
per_device_train_batch_size=4
per_device_eval_batch_size=4
gradient_accumulation_steps=8
max_seq_length=512
output_dir=/media/hnu/hnu2023/huangzhan/training/alpaca/6/output/lora4
validation_file=/media/hnu/hnu2023/huangzhan/training/alpaca/6/val.json

deepspeed_config_file=ds_zero2_no_offload.json

torchrun --nnodes 1 --nproc_per_node 1 run_clm_sft_with_peft.py \
    --deepspeed ${deepspeed_config_file} \
    --model_name_or_path ${pretrained_model} \
    --tokenizer_name_or_path ${chinese_tokenizer_path} \
    --dataset_dir ${dataset_dir} \
    --per_device_train_batch_size ${per_device_train_batch_size} \
    --per_device_eval_batch_size ${per_device_eval_batch_size} \
    --do_train \
    --do_eval \
    --seed $RANDOM \
    --fp16 \
    --num_train_epochs 1 \
    --lr_scheduler_type cosine \
    --learning_rate ${lr} \
    --warmup_ratio 0.03 \
    --weight_decay 0 \
    --logging_strategy steps \
    --logging_steps 4 \
    --save_strategy steps \
    --save_total_limit 3 \
    --evaluation_strategy steps \
    --eval_steps 10 \
    --save_steps 100 \
    --gradient_accumulation_steps ${gradient_accumulation_steps} \
    --preprocessing_num_workers 8 \
    --max_seq_length ${max_seq_length} \
    --output_dir ${output_dir} \
    --overwrite_output_dir \
    --ddp_timeout 30000 \
    --logging_first_step True \
    --lora_rank ${lora_rank} \
    --lora_alpha ${lora_alpha} \
    --trainable ${lora_trainable} \
    --lora_dropout ${lora_dropout} \
    --torch_dtype float16 \
    --validation_file ${validation_file} \
    --load_in_kbits 16 \
    --gradient_checkpointing \
    --ddp_find_unused_parameters False \
          --flash_attn
